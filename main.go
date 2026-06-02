package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/plugin-aws-apigateway/internal"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
)

type CompliancePlugin struct {
	logger     hclog.Logger
	config     *internal.PluginConfig
	policyData map[string]interface{}
}

func (l *CompliancePlugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	parsedConfig, err := internal.ParseConfig(req.GetConfig())
	if err != nil {
		return nil, err
	}
	l.config = parsedConfig
	if req.GetPolicyData() != nil {
		l.policyData = req.GetPolicyData().AsMap()
	}
	return &proto.ConfigureResponse{}, nil
}

func (l *CompliancePlugin) Init(req *proto.InitRequest, apiHelper runner.ApiHelper) (*proto.InitResponse, error) {
	ctx := context.Background()
	subjectTemplates := []*proto.SubjectTemplate{
		{
			Name:                "apigateway-domain",
			Type:                proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			TitleTemplate:       "API Gateway Domain {{ .domain_name }}",
			DescriptionTemplate: "AWS API Gateway custom domain {{ .domain_name }} in {{ .account_id }}/{{ .region }}.",
			PurposeTemplate:     "Represents an AWS API Gateway custom domain evaluated for TLS compliance posture.",
			IdentityLabelKeys:   []string{"account_id", "region", "domain_name"},
			LabelSchema: []*proto.SubjectLabelSchema{
				{Key: "account_id", Description: "AWS account ID"},
				{Key: "region", Description: "AWS region"},
				{Key: "domain_name", Description: "API Gateway custom domain name"},
			},
		},
	}
	return runner.InitWithSubjectsAndRisksFromPolicies(ctx, l.logger, req, apiHelper, subjectTemplates)
}

func (l *CompliancePlugin) Eval(request *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {
	ctx := context.Background()
	activities := make([]*proto.Activity, 0)

	if request == nil {
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, fmt.Errorf("eval request is nil")
	}

	dataFetcher := internal.NewDataFetcher(l.logger, l.config)
	domains, err := dataFetcher.FetchData(ctx)
	if err != nil {
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, fmt.Errorf("failed to fetch data: %w", err)
	}

	policyEvaluator := internal.NewPolicyEvaluator(ctx, l.logger, activities)

	var allEvidences []*proto.Evidence
	var evalErrors error
	for _, domain := range domains {
		domainEvidences, err := policyEvaluator.Eval(ctx, domain, request.GetPolicyPaths(), l.policyData, l.config.PolicyLabels)
		allEvidences = append(allEvidences, domainEvidences...)
		if err != nil {
			evalErrors = errors.Join(evalErrors, fmt.Errorf("evaluating domain %s: %w", domain.DomainName, err))
		}
	}

	if err := apiHelper.CreateEvidence(ctx, allEvidences); err != nil {
		l.logger.Error("Error creating evidence", "error", err)
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, err
	}

	if evalErrors != nil {
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, evalErrors
	}

	return &proto.EvalResponse{Status: proto.ExecutionStatus_SUCCESS}, nil
}

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Debug,
		JSONFormat: true,
	})

	compliancePluginObj := &CompliancePlugin{logger: logger}
	logger.Debug("initiating plugin")

	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: runner.HandshakeConfig,
		Plugins: map[string]goplugin.Plugin{
			"runner": &runner.RunnerV2GRPCPlugin{Impl: compliancePluginObj},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}
