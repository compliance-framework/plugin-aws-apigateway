package internal

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/hashicorp/go-hclog"
)

type mockAPIGWClient struct {
	getDomainNames func(context.Context, *apigateway.GetDomainNamesInput, ...func(*apigateway.Options)) (*apigateway.GetDomainNamesOutput, error)
}

func (m *mockAPIGWClient) GetDomainNames(ctx context.Context, params *apigateway.GetDomainNamesInput, optFns ...func(*apigateway.Options)) (*apigateway.GetDomainNamesOutput, error) {
	return m.getDomainNames(ctx, params, optFns...)
}

type mockSTSClient struct {
	getCallerIdentity func(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

func (m *mockSTSClient) GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return m.getCallerIdentity(ctx, params, optFns...)
}

func defaultSTSMock() *mockSTSClient {
	return &mockSTSClient{
		getCallerIdentity: func(_ context.Context, _ *sts.GetCallerIdentityInput, _ ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{Account: aws.String("123456789012")}, nil
		},
	}
}

func newTestFetcher(regions []string, client APIGatewayClient) *DataFetcher {
	return &DataFetcher{
		logger: hclog.NewNullLogger(),
		config: &PluginConfig{Regions: regions},
		newClient: func(_ context.Context, _ string) (APIGatewayClient, error) {
			return client, nil
		},
		newSTSClient: func(_ context.Context) (STSClient, error) {
			return defaultSTSMock(), nil
		},
	}
}

func TestFetchData_Empty(t *testing.T) {
	mock := &mockAPIGWClient{
		getDomainNames: func(_ context.Context, _ *apigateway.GetDomainNamesInput, _ ...func(*apigateway.Options)) (*apigateway.GetDomainNamesOutput, error) {
			return &apigateway.GetDomainNamesOutput{}, nil
		},
	}
	f := newTestFetcher([]string{"us-east-1"}, mock)
	domains, err := f.FetchData(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(domains) != 0 {
		t.Errorf("expected 0 domains, got %d", len(domains))
	}
}

func TestFetchData_SingleDomain(t *testing.T) {
	mock := &mockAPIGWClient{
		getDomainNames: func(_ context.Context, _ *apigateway.GetDomainNamesInput, _ ...func(*apigateway.Options)) (*apigateway.GetDomainNamesOutput, error) {
			return &apigateway.GetDomainNamesOutput{
				Items: []types.DomainName{
					{
						DomainName:                aws.String("api.example.com"),
						SecurityPolicy:            types.SecurityPolicyTls12,
						RegionalCertificateArn:    aws.String("arn:aws:acm:us-east-1:123456789012:certificate/abc-123"),
						DomainNameStatus:          types.DomainNameStatusAvailable,
						EndpointConfiguration:     &types.EndpointConfiguration{Types: []types.EndpointType{types.EndpointTypeRegional}},
						Tags:                      map[string]string{"env": "prod"},
					},
				},
			}, nil
		},
	}

	f := newTestFetcher([]string{"us-east-1"}, mock)
	domains, err := f.FetchData(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(domains) != 1 {
		t.Fatalf("expected 1 domain, got %d", len(domains))
	}

	d := domains[0]
	if d.DomainName != "api.example.com" {
		t.Errorf("domain_name: want %q, got %q", "api.example.com", d.DomainName)
	}
	if d.SecurityPolicy != "TLS_1_2" {
		t.Errorf("security_policy: want %q, got %q", "TLS_1_2", d.SecurityPolicy)
	}
	if d.CertificateArn != "arn:aws:acm:us-east-1:123456789012:certificate/abc-123" {
		t.Errorf("certificate_arn: want regional ARN, got %q", d.CertificateArn)
	}
	if d.EndpointType != "REGIONAL" {
		t.Errorf("endpoint_type: want %q, got %q", "REGIONAL", d.EndpointType)
	}
	if d.Region != "us-east-1" {
		t.Errorf("region: want %q, got %q", "us-east-1", d.Region)
	}
	if d.AccountID != "123456789012" {
		t.Errorf("account_id: want %q, got %q", "123456789012", d.AccountID)
	}
	if d.Tags["env"] != "prod" {
		t.Errorf("tags: expected env=prod, got %v", d.Tags)
	}
}

func TestFetchData_PreferRegionalCertArn(t *testing.T) {
	mock := &mockAPIGWClient{
		getDomainNames: func(_ context.Context, _ *apigateway.GetDomainNamesInput, _ ...func(*apigateway.Options)) (*apigateway.GetDomainNamesOutput, error) {
			return &apigateway.GetDomainNamesOutput{
				Items: []types.DomainName{
					{
						DomainName:             aws.String("api.example.com"),
						SecurityPolicy:         types.SecurityPolicyTls12,
						CertificateArn:         aws.String("arn:aws:acm:us-east-1:123456789012:certificate/edge-cert"),
						RegionalCertificateArn: aws.String("arn:aws:acm:us-east-1:123456789012:certificate/regional-cert"),
					},
				},
			}, nil
		},
	}

	f := newTestFetcher([]string{"us-east-1"}, mock)
	domains, err := f.FetchData(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if domains[0].CertificateArn != "arn:aws:acm:us-east-1:123456789012:certificate/regional-cert" {
		t.Errorf("should prefer regional cert ARN, got %q", domains[0].CertificateArn)
	}
}

func TestFetchData_Pagination(t *testing.T) {
	callCount := 0
	mock := &mockAPIGWClient{
		getDomainNames: func(_ context.Context, params *apigateway.GetDomainNamesInput, _ ...func(*apigateway.Options)) (*apigateway.GetDomainNamesOutput, error) {
			callCount++
			if callCount == 1 {
				return &apigateway.GetDomainNamesOutput{
					Items:    []types.DomainName{{DomainName: aws.String("a.example.com"), SecurityPolicy: types.SecurityPolicyTls12}},
					Position: aws.String("page2"),
				}, nil
			}
			return &apigateway.GetDomainNamesOutput{
				Items: []types.DomainName{{DomainName: aws.String("b.example.com"), SecurityPolicy: types.SecurityPolicyTls12}},
			}, nil
		},
	}

	f := newTestFetcher([]string{"us-east-1"}, mock)
	domains, err := f.FetchData(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(domains) != 2 {
		t.Errorf("expected 2 domains, got %d", len(domains))
	}
	if callCount != 2 {
		t.Errorf("expected 2 GetDomainNames calls, got %d", callCount)
	}
}

func TestFetchData_MultipleRegions(t *testing.T) {
	var clientRegions []string
	f := &DataFetcher{
		logger: hclog.NewNullLogger(),
		config: &PluginConfig{Regions: []string{"us-east-1", "eu-west-1"}},
		newClient: func(_ context.Context, region string) (APIGatewayClient, error) {
			clientRegions = append(clientRegions, region)
			return &mockAPIGWClient{
				getDomainNames: func(_ context.Context, _ *apigateway.GetDomainNamesInput, _ ...func(*apigateway.Options)) (*apigateway.GetDomainNamesOutput, error) {
					return &apigateway.GetDomainNamesOutput{}, nil
				},
			}, nil
		},
		newSTSClient: func(_ context.Context) (STSClient, error) { return defaultSTSMock(), nil },
	}

	_, err := f.FetchData(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(clientRegions) != 2 || clientRegions[0] != "us-east-1" || clientRegions[1] != "eu-west-1" {
		t.Errorf("expected clients for us-east-1 and eu-west-1, got %v", clientRegions)
	}
}
