// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"context"
	"encoding/json"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

const (
	maxEventFieldLen = 512 // max length for any CloudTrail-derived field
)

// safeEventFieldRE allows only characters valid in AWS resource identifiers.
// This prevents log injection, Cedar injection, and control-flow surprises.
var safeEventFieldRE = regexp.MustCompile(`^[a-zA-Z0-9._/:@\-]+$`)

// sanitizeEventField truncates and strips unsafe characters from CloudTrail
// event fields before they are used in Cedar evaluation or log writes.
func sanitizeEventField(s string) string {
	if len(s) > maxEventFieldLen {
		s = s[:maxEventFieldLen]
	}
	if safeEventFieldRE.MatchString(s) {
		return s
	}
	// Replace any character outside the safe set with underscore.
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '_' ||
			c == '/' || c == ':' || c == '@' || c == '-' {
			result[i] = c
		} else {
			result[i] = '_'
		}
	}
	return string(result)
}

// cloudTrailPoller polls CloudTrail for recent management events and
// translates them into AuthzRequests for Cedar evaluation.
type cloudTrailPoller struct {
	svc *cloudtrail.Client
}

func newCloudTrailPoller(svc *cloudtrail.Client) *cloudTrailPoller {
	return &cloudTrailPoller{svc: svc}
}

// Poll returns events that occurred between from and to, translated into
// AuthzRequests. Events that cannot be mapped are silently skipped.
func (p *cloudTrailPoller) Poll(ctx context.Context, from, to time.Time) ([]*AuthzRequest, error) {
	out, err := p.svc.LookupEvents(ctx, &cloudtrail.LookupEventsInput{
		StartTime: aws.Time(from),
		EndTime:   aws.Time(to),
		MaxResults: aws.Int32(50),
	})
	if err != nil {
		return nil, err
	}

	var reqs []*AuthzRequest
	for _, ev := range out.Events {
		req := translateEvent(ev)
		if req != nil {
			reqs = append(reqs, req)
		}
	}
	return reqs, nil
}

// translateEvent converts a CloudTrail event into an AuthzRequest.
// Returns nil for events that cannot be meaningfully evaluated.
func translateEvent(ev cttypes.Event) *AuthzRequest {
	if ev.EventName == nil {
		return nil
	}

	// Build principal from username — sanitize before use.
	principalARN := "arn:aws:iam::unknown:user/unknown"
	if ev.Username != nil {
		principalARN = "arn:aws:iam::unknown:user/" + sanitizeEventField(*ev.Username)
	}

	// Extract account from CloudTrail record details.
	accountID := ""
	if ev.CloudTrailEvent != nil {
		var raw map[string]any
		if err := json.Unmarshal([]byte(*ev.CloudTrailEvent), &raw); err == nil {
			if userIdentity, ok := raw["userIdentity"].(map[string]any); ok {
				if acct, ok := userIdentity["accountId"].(string); ok {
					accountID = acct
				}
				if arn, ok := userIdentity["arn"].(string); ok && arn != "" {
					principalARN = sanitizeEventField(arn)
				}
			}
		}
	}

	// Use resource name as resource identifier — sanitize before use.
	resourceARN := "*"
	for _, r := range ev.Resources {
		if r.ResourceName != nil {
			resourceARN = sanitizeEventField(aws.ToString(r.ResourceName))
			break
		}
	}

	ts := time.Now()
	if ev.EventTime != nil {
		ts = *ev.EventTime
	}

	return &AuthzRequest{
		Action:       sanitizeEventField(aws.ToString(ev.EventName)),
		PrincipalARN: principalARN,
		ResourceARN:  resourceARN,
		AccountID:    accountID,
		Attributes:   map[string]any{},
		Timestamp:    ts,
	}
}
