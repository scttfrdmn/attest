// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package deploy provides CloudFormation stack deployment alongside the
// existing Organizations SCP deployer. CFNDeployer follows the identical
// pattern as ground's internal/deploy/deployer.go.
package deploy

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
)

// CFNResult describes the outcome of a CFNDeployer.Deploy call.
type CFNResult struct {
	StackName string
	StackID   string
	Status    string
	Created   bool
}

// CFNDeployer deploys CloudFormation stacks for attest-managed resources
// (provenance lifecycle rules, Config rules, etc.).
type CFNDeployer struct {
	cf     *cloudformation.Client
	region string
}

// NewCFNDeployer creates a CFNDeployer using the default AWS credential chain.
func NewCFNDeployer(ctx context.Context, region string) (*CFNDeployer, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	return &CFNDeployer{cf: cloudformation.NewFromConfig(cfg), region: region}, nil
}

// Deploy creates or updates a CloudFormation stack, blocking until terminal state.
func (d *CFNDeployer) Deploy(ctx context.Context, stackName, templateBody string) (*CFNResult, error) {
	existing, err := d.describe(ctx, stackName)
	if err != nil && !isCFNNotFound(err) {
		return nil, fmt.Errorf("describe %s: %w", stackName, err)
	}

	var stackID string
	created := false

	if existing == nil {
		out, createErr := d.cf.CreateStack(ctx, &cloudformation.CreateStackInput{
			StackName:    aws.String(stackName),
			TemplateBody: aws.String(templateBody),
			Capabilities: []cftypes.Capability{
				cftypes.CapabilityCapabilityIam,
				cftypes.CapabilityCapabilityNamedIam,
			},
			Tags: []cftypes.Tag{
				{Key: aws.String("managed-by"), Value: aws.String("attest")},
			},
		})
		if createErr != nil {
			return nil, fmt.Errorf("create stack %s: %w", stackName, createErr)
		}
		stackID = aws.ToString(out.StackId)
		created = true
	} else {
		_, updateErr := d.cf.UpdateStack(ctx, &cloudformation.UpdateStackInput{
			StackName:    aws.String(stackName),
			TemplateBody: aws.String(templateBody),
			Capabilities: []cftypes.Capability{
				cftypes.CapabilityCapabilityIam,
				cftypes.CapabilityCapabilityNamedIam,
			},
		})
		if updateErr != nil {
			if isCFNNoUpdates(updateErr) {
				return &CFNResult{
					StackName: stackName,
					StackID:   aws.ToString(existing.StackId),
					Status:    string(existing.StackStatus),
				}, nil
			}
			return nil, fmt.Errorf("update stack %s: %w", stackName, updateErr)
		}
		stackID = aws.ToString(existing.StackId)
	}

	finalStatus, pollErr := d.poll(ctx, stackName)
	if pollErr != nil {
		return nil, fmt.Errorf("stack %s: %w", stackName, pollErr)
	}
	return &CFNResult{StackName: stackName, StackID: stackID, Status: finalStatus, Created: created}, nil
}

// Status returns the current status of a CloudFormation stack, or "NOT_FOUND".
func (d *CFNDeployer) Status(ctx context.Context, stackName string) (string, error) {
	stack, err := d.describe(ctx, stackName)
	if err != nil {
		if isCFNNotFound(err) {
			return "NOT_FOUND", nil
		}
		return "", fmt.Errorf("describe %s: %w", stackName, err)
	}
	return string(stack.StackStatus), nil
}

func (d *CFNDeployer) describe(ctx context.Context, stackName string) (*cftypes.Stack, error) {
	out, err := d.cf.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{
		StackName: aws.String(stackName),
	})
	if err != nil {
		return nil, err
	}
	if len(out.Stacks) == 0 {
		return nil, nil
	}
	return &out.Stacks[0], nil
}

func (d *CFNDeployer) poll(ctx context.Context, stackName string) (string, error) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-ticker.C:
			stack, err := d.describe(ctx, stackName)
			if err != nil {
				return "", err
			}
			if stack == nil {
				return "DELETED", nil
			}
			status := string(stack.StackStatus)
			if isCFNTerminal(status) {
				if isCFNFailure(status) {
					return status, fmt.Errorf("stack reached %s: %s", status, aws.ToString(stack.StackStatusReason))
				}
				return status, nil
			}
		}
	}
}

func isCFNTerminal(status string) bool {
	switch cftypes.StackStatus(status) {
	case cftypes.StackStatusCreateComplete, cftypes.StackStatusCreateFailed,
		cftypes.StackStatusUpdateComplete, cftypes.StackStatusUpdateFailed,
		cftypes.StackStatusUpdateRollbackComplete, cftypes.StackStatusUpdateRollbackFailed,
		cftypes.StackStatusRollbackComplete, cftypes.StackStatusRollbackFailed,
		cftypes.StackStatusDeleteComplete, cftypes.StackStatusDeleteFailed:
		return true
	}
	return false
}

func isCFNFailure(status string) bool {
	switch cftypes.StackStatus(status) {
	case cftypes.StackStatusCreateFailed, cftypes.StackStatusUpdateFailed,
		cftypes.StackStatusUpdateRollbackFailed, cftypes.StackStatusRollbackFailed,
		cftypes.StackStatusDeleteFailed:
		return true
	}
	return false
}

func isCFNNotFound(err error) bool {
	var ae interface{ ErrorCode() string }
	return errors.As(err, &ae) && ae.ErrorCode() == "ValidationError"
}

func isCFNNoUpdates(err error) bool {
	return err != nil && fmt.Sprintf("%v", err) == "ValidationError: No updates are to be performed."
}
