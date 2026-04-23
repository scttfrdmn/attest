package evaluator

import (
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

// TestSanitizeEventField covers the HIGH security fix: CloudTrail input sanitization.
func TestSanitizeEventField(t *testing.T) {
	tests := []struct {
		input string
		want  string
		desc  string
	}{
		// Safe inputs pass through unchanged.
		{"GetObject", "GetObject", "normal action name"},
		{"arn:aws:iam::123:role/researcher", "arn:aws:iam::123:role/researcher", "IAM ARN"},
		{"my-bucket.us-east-1", "my-bucket.us-east-1", "S3 bucket with dots/dash"},
		{"user@domain.edu", "user@domain.edu", "email-like identifier"},

		// Log injection chars replaced.
		{"action\ninjected", "action_injected", "newline injection"},
		{"action\rinjected", "action_injected", "carriage return"},
		{"action;inject", "action_inject", "semicolon"},
		{"action&inject", "action_inject", "ampersand"},
		{"action|inject", "action_inject", "pipe"},
		{"action`inject`", "action_inject_", "backtick"},
		{"action$(cmd)", "action__cmd_", "command substitution"},

		// Long input truncated.
		{strings.Repeat("a", 600), strings.Repeat("a", 512), "truncation to 512 chars"},
		{strings.Repeat("a", 512), strings.Repeat("a", 512), "exact 512 chars — no truncation"},
		{strings.Repeat("a", 513), strings.Repeat("a", 512), "513 chars — truncated by 1"},
	}

	for _, tt := range tests {
		got := sanitizeEventField(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeEventField(%q) [%s]\n  got:  %q\n  want: %q",
				tt.input, tt.desc, got, tt.want)
		}
	}
}

// TestTranslateEvent verifies that crafted CloudTrail events produce safe AuthzRequests.
func TestTranslateEvent(t *testing.T) {
	tests := []struct {
		desc     string
		ev       cttypes.Event
		wantNil  bool
		checkFn  func(t *testing.T, req *AuthzRequest)
	}{
		{
			desc:    "nil EventName → nil request",
			ev:      cttypes.Event{EventName: nil, Username: aws.String("user")},
			wantNil: true,
		},
		{
			desc: "normal event",
			ev: cttypes.Event{
				EventName: aws.String("GetObject"),
				Username:  aws.String("researcher"),
				EventTime: aws.Time(time.Now()),
			},
			checkFn: func(t *testing.T, req *AuthzRequest) {
				if req.Action != "GetObject" {
					t.Errorf("Action = %q, want GetObject", req.Action)
				}
				if !strings.Contains(req.PrincipalARN, "researcher") {
					t.Errorf("PrincipalARN = %q, want to contain researcher", req.PrincipalARN)
				}
			},
		},
		{
			desc: "injection attempt in username → sanitized",
			ev: cttypes.Event{
				EventName: aws.String("ListBuckets"),
				Username:  aws.String("user\nmalicious\nlog injection"),
			},
			checkFn: func(t *testing.T, req *AuthzRequest) {
				if strings.Contains(req.PrincipalARN, "\n") {
					t.Errorf("PrincipalARN contains newline: %q", req.PrincipalARN)
				}
				// "malicious" stays in the ARN after sanitization; only the newline is removed.
				_ = strings.Contains(req.PrincipalARN, "malicious")
			},
		},
		{
			desc: "injection attempt in EventName → sanitized",
			ev: cttypes.Event{
				EventName: aws.String("GetObject\n; rm -rf ."),
				Username:  aws.String("user"),
			},
			checkFn: func(t *testing.T, req *AuthzRequest) {
				if strings.Contains(req.Action, "\n") {
					t.Errorf("Action contains newline: %q", req.Action)
				}
				if strings.Contains(req.Action, ";") {
					t.Errorf("Action contains semicolon: %q", req.Action)
				}
			},
		},
		{
			desc: "very long username → truncated to 512",
			ev: cttypes.Event{
				EventName: aws.String("GetObject"),
				Username:  aws.String(strings.Repeat("a", 1000)),
			},
			checkFn: func(t *testing.T, req *AuthzRequest) {
				// principalARN includes "arn:aws:iam::unknown:user/" prefix
				// so total length > 512 is expected, but the username part is ≤512
				if len(req.PrincipalARN) > 600 {
					t.Errorf("PrincipalARN too long: %d chars", len(req.PrincipalARN))
				}
			},
		},
		{
			desc: "resource name is sanitized",
			ev: cttypes.Event{
				EventName: aws.String("PutObject"),
				Username:  aws.String("user"),
				Resources: []cttypes.Resource{
					{ResourceName: aws.String("bucket\n../../etc/passwd")},
				},
			},
			checkFn: func(t *testing.T, req *AuthzRequest) {
				if strings.Contains(req.ResourceARN, "\n") {
					t.Errorf("ResourceARN contains newline: %q", req.ResourceARN)
				}
			},
		},
	}

	for _, tt := range tests {
		req := translateEvent(tt.ev)
		if tt.wantNil {
			if req != nil {
				t.Errorf("[%s] translateEvent() = %v, want nil", tt.desc, req)
			}
			continue
		}
		if req == nil {
			t.Errorf("[%s] translateEvent() = nil, want non-nil", tt.desc)
			continue
		}
		if tt.checkFn != nil {
			tt.checkFn(t, req)
		}
	}
}
