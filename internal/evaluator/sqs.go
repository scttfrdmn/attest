// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"context"
	"encoding/json"
	"fmt"
	neturl "net/url"
	"os"
	"path/filepath"
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

func newSQSPoller(svc *sqs.Client, queueURL string) (*sqsPoller, error) {
	// Validate queue URL format to prevent SSRF via hand-edited evaluator.yaml.
	// Use URL parsing with hostname check — substring matching is vulnerable to
	// subdomain confusion: https://sqs.us-east-1.amazonaws.com.evil.com/...
	// passes HasPrefix("https://sqs.") AND Contains(".amazonaws.com/").
	u, err := neturl.Parse(queueURL)
	if err != nil || u.Scheme != "https" {
		return nil, fmt.Errorf("invalid SQS queue URL: must use https scheme")
	}
	host := u.Hostname()
	// Host must be exactly sqs.<region>.amazonaws.com — not a subdomain of it.
	if !strings.HasSuffix(host, ".amazonaws.com") ||
		!strings.HasPrefix(host, "sqs.") ||
		strings.Count(host, ".") < 3 { // sqs.us-east-1.amazonaws.com has 3 dots
		return nil, fmt.Errorf("invalid SQS queue URL hostname %q: must be sqs.<region>.amazonaws.com", host)
	}
	return &sqsPoller{svc: svc, queueURL: queueURL}, nil
}

// messageRecord binds a set of AuthzRequests to the SQS receipt handle of the
// originating message. This ensures the correct message is deleted after its
// requests are processed — regardless of how many requests translateSQSMessage
// extracts per message (0, 1, or many).
type messageRecord struct {
	reqs   []*AuthzRequest
	handle string
}

// Poll performs a long-poll (20s wait) on the SQS queue and returns per-message
// records. Each record links the parsed requests to their SQS receipt handle so
// that only successfully-evaluated messages are deleted.
func (p *sqsPoller) Poll(ctx context.Context) ([]messageRecord, error) {
	out, err := p.svc.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
		QueueUrl:            aws.String(p.queueURL),
		MaxNumberOfMessages: 10,
		WaitTimeSeconds:     20,
	})
	if err != nil {
		return nil, fmt.Errorf("SQS ReceiveMessage: %w", err)
	}

	var records []messageRecord
	for _, msg := range out.Messages {
		reqs := translateSQSMessage(msg)
		handle := ""
		if msg.ReceiptHandle != nil {
			handle = *msg.ReceiptHandle
		}
		// Include all messages in the record list — even those that produced
		// no AuthzRequests — so their handles can be deleted (non-CloudTrail
		// messages should be removed from the queue, not redelivered endlessly).
		records = append(records, messageRecord{reqs: reqs, handle: handle})
	}
	return records, nil
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
	logFile, err := os.OpenFile(filepath.Join(historyDir, "cedar-decisions.jsonl"),
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

	poller, err := newSQSPoller(sqsSvc, queueURL)
	if err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		records, err := poller.Poll(ctx)
		if err != nil {
			if strings.Contains(err.Error(), "context") {
				return nil
			}
			continue
		}

		// Process each message record. A record may contain zero requests (e.g.,
		// non-CloudTrail EventBridge messages) — these are still deleted so they
		// don't stay in the queue and get redelivered endlessly.
		var toDelete []string
		for _, record := range records {
			allSucceeded := true
			for _, req := range record.reqs {
				decision, err := e.EvaluateWithPolicies(ctx, ps, req)
				if err != nil {
					allSucceeded = false
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
			}
			// Delete the message if all its requests were processed (or it had
			// no requests — non-CloudTrail messages we don't want redelivered).
			if allSucceeded && record.handle != "" {
				toDelete = append(toDelete, record.handle)
			}
		}
		if len(toDelete) > 0 {
			_ = poller.DeleteProcessed(ctx, toDelete)
		}
	}
}
