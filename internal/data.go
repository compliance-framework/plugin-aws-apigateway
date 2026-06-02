package internal

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/hashicorp/go-hclog"
)

// APIGatewayClient is the subset of the AWS API Gateway REST API used by DataFetcher.
type APIGatewayClient interface {
	GetDomainNames(ctx context.Context, params *apigateway.GetDomainNamesInput, optFns ...func(*apigateway.Options)) (*apigateway.GetDomainNamesOutput, error)
}

// STSClient is used to determine the AWS account ID.
type STSClient interface {
	GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// DomainContext holds all fields required by API Gateway compliance policies.
type DomainContext struct {
	Region         string            `json:"region"`
	AccountID      string            `json:"account_id"`
	DomainName     string            `json:"domain_name"`
	SecurityPolicy string            `json:"security_policy"`
	CertificateArn string            `json:"certificate_arn,omitempty"`
	EndpointType   string            `json:"endpoint_type"`
	Status         string            `json:"status"`
	Tags           map[string]string `json:"tags"`
}

// ToOPAInput serialises d to a map[string]interface{} suitable for OPA input.
func (d DomainContext) ToOPAInput() (map[string]interface{}, error) {
	b, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// DataFetcher retrieves API Gateway custom domain data across configured regions.
type DataFetcher struct {
	logger       hclog.Logger
	config       *PluginConfig
	newClient    func(ctx context.Context, region string) (APIGatewayClient, error)
	newSTSClient func(ctx context.Context) (STSClient, error)
}

// NewDataFetcher returns a DataFetcher using the standard AWS credential chain.
func NewDataFetcher(logger hclog.Logger, cfg *PluginConfig) *DataFetcher {
	return &DataFetcher{
		logger: logger,
		config: cfg,
		newClient: func(ctx context.Context, region string) (APIGatewayClient, error) {
			awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
			if err != nil {
				return nil, err
			}
			return apigateway.NewFromConfig(awsCfg), nil
		},
		newSTSClient: func(ctx context.Context) (STSClient, error) {
			awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.Regions[0]))
			if err != nil {
				return nil, err
			}
			return sts.NewFromConfig(awsCfg), nil
		},
	}
}

// FetchData retrieves all API Gateway custom domains across every configured region.
func (df *DataFetcher) FetchData(ctx context.Context) ([]DomainContext, error) {
	stsClient, err := df.newSTSClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create STS client: %w", err)
	}
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("GetCallerIdentity: %w", err)
	}
	accountID := aws.ToString(identity.Account)

	var all []DomainContext
	for _, region := range df.config.Regions {
		domains, err := df.fetchRegion(ctx, region, accountID)
		if err != nil {
			return nil, fmt.Errorf("region %s: %w", region, err)
		}
		all = append(all, domains...)
	}
	return all, nil
}

func (df *DataFetcher) fetchRegion(ctx context.Context, region, accountID string) ([]DomainContext, error) {
	client, err := df.newClient(ctx, region)
	if err != nil {
		return nil, fmt.Errorf("create API Gateway client: %w", err)
	}

	var domains []DomainContext
	var position *string
	for {
		out, err := client.GetDomainNames(ctx, &apigateway.GetDomainNamesInput{
			Position: position,
		})
		if err != nil {
			return nil, fmt.Errorf("GetDomainNames: %w", err)
		}
		for _, item := range out.Items {
			domains = append(domains, buildDomainContext(region, accountID, item))
		}
		if out.Position == nil {
			break
		}
		position = out.Position
	}
	return domains, nil
}

func buildDomainContext(region, accountID string, d types.DomainName) DomainContext {
	// Prefer regional certificate ARN; fall back to edge-optimized.
	certArn := aws.ToString(d.RegionalCertificateArn)
	if certArn == "" {
		certArn = aws.ToString(d.CertificateArn)
	}

	endpointType := ""
	if d.EndpointConfiguration != nil && len(d.EndpointConfiguration.Types) > 0 {
		endpointType = string(d.EndpointConfiguration.Types[0])
	}

	tags := make(map[string]string, len(d.Tags))
	for k, v := range d.Tags {
		tags[k] = v
	}

	return DomainContext{
		Region:         region,
		AccountID:      accountID,
		DomainName:     aws.ToString(d.DomainName),
		SecurityPolicy: string(d.SecurityPolicy),
		CertificateArn: certArn,
		EndpointType:   endpointType,
		Status:         string(d.DomainNameStatus),
		Tags:           tags,
	}
}
