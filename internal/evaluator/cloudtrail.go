package evaluator

import (
	"context"
	"encoding/json"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

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

	// Build principal from username.
	principalARN := "arn:aws:iam::unknown:user/unknown"
	if ev.Username != nil {
		principalARN = "arn:aws:iam::unknown:user/" + *ev.Username
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
					principalARN = arn
				}
			}
		}
	}

	// Use resource name as resource identifier.
	resourceARN := "*"
	for _, r := range ev.Resources {
		if r.ResourceName != nil {
			resourceARN = aws.ToString(r.ResourceName)
			break
		}
	}

	ts := time.Now()
	if ev.EventTime != nil {
		ts = *ev.EventTime
	}

	return &AuthzRequest{
		Action:       aws.ToString(ev.EventName),
		PrincipalARN: principalARN,
		ResourceARN:  resourceARN,
		AccountID:    accountID,
		Attributes:   map[string]any{},
		Timestamp:    ts,
	}
}
