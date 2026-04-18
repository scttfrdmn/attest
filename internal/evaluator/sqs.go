package evaluator

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

// sqsPoller consumes CloudTrail events delivered by EventBridge via SQS.
// This is the production Cedar PDP transport — events arrive within seconds
// vs. the 30s polling lag of the CloudTrail poller.
type sqsPoller struct {
	svc      *sqs.Client
	queueURL string
}

func newSQSPoller(svc *sqs.Client, queueURL string) *sqsPoller {
	return &sqsPoller{svc: svc, queueURL: queueURL}
}

// Poll performs a long-poll (20s wait) on the SQS queue and returns translated
// AuthzRequests along with the receipt handles needed to delete processed messages.
func (p *sqsPoller) Poll(ctx context.Context) ([]*AuthzRequest, []string, error) {
	out, err := p.svc.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
		QueueUrl:            aws.String(p.queueURL),
		MaxNumberOfMessages: 10,
		WaitTimeSeconds:     20,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("SQS ReceiveMessage: %w", err)
	}

	var reqs []*AuthzRequest
	var handles []string
	for _, msg := range out.Messages {
		reqs = append(reqs, translateSQSMessage(msg)...)
		if msg.ReceiptHandle != nil {
			handles = append(handles, *msg.ReceiptHandle)
		}
	}
	return reqs, handles, nil
}

// DeleteProcessed removes successfully-evaluated messages from the queue.
func (p *sqsPoller) DeleteProcessed(ctx context.Context, handles []string) error {
	if len(handles) == 0 {
		return nil
	}
	var entries []sqstypes.DeleteMessageBatchRequestEntry
	for i, h := range handles {
		h := h
		entries = append(entries, sqstypes.DeleteMessageBatchRequestEntry{
			Id:            aws.String(fmt.Sprintf("msg-%d", i)),
			ReceiptHandle: aws.String(h),
		})
	}
	_, err := p.svc.DeleteMessageBatch(ctx, &sqs.DeleteMessageBatchInput{
		QueueUrl: aws.String(p.queueURL),
		Entries:  entries,
	})
	return err
}

// translateSQSMessage parses an EventBridge-wrapped CloudTrail event from an SQS
// message and returns the equivalent AuthzRequest(s). Returns nil for non-CloudTrail.
func translateSQSMessage(msg sqstypes.Message) []*AuthzRequest {
	if msg.Body == nil {
		return nil
	}
	var envelope struct {
		Source string         `json:"source"`
		Detail map[string]any `json:"detail"`
		Time   time.Time      `json:"time"`
	}
	if err := json.Unmarshal([]byte(*msg.Body), &envelope); err != nil {
		return nil
	}
	if envelope.Source != "aws.cloudtrail" {
		return nil
	}

	detail := envelope.Detail
	eventName, _ := detail["eventName"].(string)
	if eventName == "" {
		return nil
	}
	eventName = sanitizeEventField(eventName)

	principalARN := "arn:aws:iam::unknown:user/unknown"
	if ui, ok := detail["userIdentity"].(map[string]any); ok {
		if arn, ok := ui["arn"].(string); ok && arn != "" {
			principalARN = sanitizeEventField(arn)
		} else if u, ok := ui["userName"].(string); ok && u != "" {
			principalARN = "arn:aws:iam::unknown:user/" + sanitizeEventField(u)
		}
	}

	accountID, _ := detail["recipientAccountId"].(string)
	accountID = sanitizeEventField(accountID)

	resourceARN := "*"
	if resources, ok := detail["resources"].([]any); ok && len(resources) > 0 {
		if r, ok := resources[0].(map[string]any); ok {
			if arn, ok := r["ARN"].(string); ok && arn != "" {
				resourceARN = sanitizeEventField(arn)
			}
		}
	}

	ts := time.Now()
	if !envelope.Time.IsZero() {
		ts = envelope.Time
	}
	return []*AuthzRequest{{
		Action:       eventName,
		PrincipalARN: principalARN,
		ResourceARN:  resourceARN,
		AccountID:    accountID,
		Attributes:   map[string]any{},
		Timestamp:    ts,
	}}
}

// StartWithSQS is like Start() but uses SQS long-polling for sub-second event delivery.
// Messages are deleted from SQS only after successful Cedar evaluation (at-least-once
// semantics — duplicate evaluations may occur if the process crashes mid-batch).
func (e *Evaluator) StartWithSQS(ctx context.Context, sqsSvc *sqs.Client, queueURL, cedarDir, historyDir string) error {
	if sqsSvc == nil || queueURL == "" {
		return fmt.Errorf("SQS client and queue URL are required")
	}

	ps, err := loadPoliciesFromDir(cedarDir)
	if err != nil {
		return fmt.Errorf("loading Cedar policies: %w", err)
	}

	if err := os.MkdirAll(historyDir, 0750); err != nil {
		return fmt.Errorf("creating history dir: %w", err)
	}
	logFile, err := os.OpenFile(historyDir+"/cedar-decisions.jsonl",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return fmt.Errorf("opening decision log: %w", err)
	}
	defer logFile.Close()

	e.mu.Lock()
	if e.broadcast == nil {
		e.broadcast = make(chan DecisionEvent, 64)
	}
	bcast := e.broadcast
	e.mu.Unlock()
	defer close(bcast)

	poller := newSQSPoller(sqsSvc, queueURL)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		reqs, handles, err := poller.Poll(ctx)
		if err != nil {
			if strings.Contains(err.Error(), "context") {
				return nil
			}
			continue
		}

		var processed []string
		for i, req := range reqs {
			decision, err := e.EvaluateWithPolicies(ctx, ps, req)
			if err != nil {
				continue
			}
			ev := DecisionEvent{
				Timestamp: decision.Timestamp,
				Action:    decision.Action,
				Principal: decision.Principal,
				Resource:  decision.Resource,
				Effect:    decision.Effect,
				PolicyID:  decision.PolicyID,
			}
			if b, err := json.Marshal(ev); err == nil {
				_, _ = logFile.Write(append(b, '\n'))
			}
			select {
			case bcast <- ev:
			default:
			}
			if i < len(handles) {
				processed = append(processed, handles[i])
			}
		}
		if len(processed) > 0 {
			_ = poller.DeleteProcessed(ctx, processed)
		}
	}
}
