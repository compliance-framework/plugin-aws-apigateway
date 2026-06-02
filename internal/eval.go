package internal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
)

type PolicyEvaluator struct {
	ctx            context.Context
	logger         hclog.Logger
	stepActivities []*proto.Activity
}

func NewPolicyEvaluator(ctx context.Context, logger hclog.Logger, stepActivities []*proto.Activity) *PolicyEvaluator {
	return &PolicyEvaluator{ctx: ctx, logger: logger, stepActivities: stepActivities}
}

func (pe *PolicyEvaluator) Eval(ctx context.Context, domain DomainContext, policyPaths []string, policyData map[string]interface{}, extraLabels map[string]string) ([]*proto.Evidence, error) {
	var accumulatedErrors error
	evidences := make([]*proto.Evidence, 0)

	input, err := domain.ToOPAInput()
	if err != nil {
		return nil, fmt.Errorf("serialising domain %s: %w", domain.DomainName, err)
	}

	componentID := "common-components/aws-apigateway"
	inventoryID := fmt.Sprintf("aws-apigateway-domain/%s/%s", domain.Region, domain.DomainName)

	labels := MergeMaps(extraLabels, domainBaseLabels(), map[string]string{
		"domain_name": domain.DomainName,
		"region":      domain.Region,
		"account_id":  domain.AccountID,
	})

	actors := []*proto.OriginActor{
		{
			Title: "The Continuous Compliance Framework",
			Type:  "assessment-platform",
			Links: []*proto.Link{
				{
					Href: "https://compliance-framework.github.io/docs/",
					Rel:  StringAddressed("reference"),
					Text: StringAddressed("The Continuous Compliance Framework"),
				},
			},
		},
		{
			Title: "Continuous Compliance Framework - AWS API Gateway Plugin",
			Type:  "tool",
			Links: []*proto.Link{
				{
					Href: "https://github.com/compliance-framework/plugin-aws-apigateway",
					Rel:  StringAddressed("reference"),
					Text: StringAddressed("The Continuous Compliance Framework AWS API Gateway Plugin"),
				},
			},
		},
	}

	components := []*proto.Component{
		{
			Identifier:  componentID,
			Type:        "service",
			Title:       "AWS API Gateway",
			Description: "Amazon API Gateway is a fully managed service for creating, publishing, and securing APIs at scale.",
			Purpose:     "To expose backend services via HTTPS endpoints with configurable TLS security policies.",
		},
	}

	inventory := []*proto.InventoryItem{
		{
			Identifier: inventoryID,
			Type:       "api-gateway-domain",
			Title:      fmt.Sprintf("AWS API Gateway Domain [%s]", domain.DomainName),
			Props: []*proto.Property{
				{Name: "domain_name", Value: domain.DomainName},
				{Name: "region", Value: domain.Region},
				{Name: "account_id", Value: domain.AccountID},
				{Name: "security_policy", Value: domain.SecurityPolicy},
				{Name: "endpoint_type", Value: domain.EndpointType},
			},
			ImplementedComponents: []*proto.InventoryItemImplementedComponent{
				{Identifier: componentID},
			},
		},
	}

	subjects := []*proto.Subject{
		{Type: proto.SubjectType_SUBJECT_TYPE_COMPONENT, Identifier: componentID},
		{Type: proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM, Identifier: inventoryID},
	}

	for _, policyPath := range policyPaths {
		rootData, err := loadBundleRootData(policyPath, policyData)
		if err != nil {
			return nil, fmt.Errorf("loading bundle data for %s: %w", policyPath, err)
		}
		processor := policyManager.NewPolicyProcessor(pe.logger, labels, subjects, components, inventory, actors, pe.stepActivities, rootData)
		evidence, perr := processor.GenerateResults(ctx, policyPath, input)
		evidences = append(evidences, evidence...)
		if perr != nil {
			accumulatedErrors = errors.Join(accumulatedErrors, perr)
		}
	}

	return evidences, accumulatedErrors
}

func domainBaseLabels() map[string]string {
	return map[string]string{
		"provider": "aws",
		"type":     "apigateway-domain",
	}
}

func loadBundleRootData(policyPath string, base map[string]interface{}) (map[string]interface{}, error) {
	candidates := []string{
		filepath.Join(filepath.Dir(policyPath), "data.json"),
		filepath.Join(policyPath, "data.json"),
	}
	for _, p := range candidates {
		raw, err := os.ReadFile(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("reading bundle data %s: %w", p, err)
		}
		var bundleData map[string]interface{}
		if err := json.Unmarshal(raw, &bundleData); err != nil {
			return nil, fmt.Errorf("parsing bundle data %s: %w", p, err)
		}
		merged := make(map[string]interface{}, len(bundleData)+len(base))
		for k, v := range bundleData {
			merged[k] = v
		}
		for k, v := range base {
			merged[k] = v
		}
		return merged, nil
	}
	return base, nil
}
