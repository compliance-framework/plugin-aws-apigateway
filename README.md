# AWS API Gateway CCF Plugin

This plugin collects read-only metadata for AWS API Gateway custom domain names, evaluates CCF Rego policy bundles against each domain, and emits evidence back through the CCF agent.

## How it fits in CCF

The CCF agent starts this binary through HashiCorp `go-plugin` (runner protocol v2), passes configuration and policy paths over gRPC, and receives generated evidence through the runner callback. This repository does not call the CCF API directly.

During `Init`, the plugin registers the `apigateway-domain` subject template (identified by `account_id`, `region` and `domain_name`) and the subject and risk templates discovered from the supplied policy bundles.

## Default policy bundle mapping

| Repository | Primary input |
| --- | --- |
| [`plugin-aws-apigateway-policies`](https://github.com/compliance-framework/plugin-aws-apigateway-policies) | one API Gateway custom domain per evaluation |

## Configuration

| Key | Required | Description |
| --- | --- | --- |
| `regions` | yes | Comma-separated list of AWS regions to scan. Empty entries are ignored. |
| `policy_labels` | no | JSON object of extra labels added to every evidence, e.g. `{"team":"platform"}`. |

AWS credentials come from the default AWS SDK credential chain. The account ID is read with `sts:GetCallerIdentity` in the first configured region.

Any agent-supplied `policy_data` is passed through to Rego as `data.*`, on top of the bundle's own `data.json` (agent-supplied keys win).

## Data collected

For every custom domain name returned by the API Gateway `GetDomainNames` API (all pages) in each configured region, the plugin builds this policy input:

| Field | Source |
| --- | --- |
| `region` | the region scanned |
| `account_id` | the caller's AWS account |
| `domain_name` | the custom domain name |
| `security_policy` | the domain's TLS security policy |
| `certificate_arn` | the regional certificate ARN, or the edge-optimized one when there is no regional certificate (omitted when neither is set) |
| `endpoint_type` | the first endpoint type (e.g. `REGIONAL`, `EDGE`) |
| `status` | the domain name status |
| `tags` | the domain's tags |

Each evidence carries the labels `provider=aws`, `type=apigateway-domain`, `domain_name`, `region` and `account_id`, plus any `policy_labels`.

## Development

Run the local test suite with:

```shell
go test ./...
```

Or use the Makefile wrapper:

```shell
make test
```

Build the plugin binary with:

```shell
make build
```

This writes the compiled plugin to `dist/plugin`.

## Releasing

- Releases come from release-please PRs: merging one tags `vX.Y.Z` and publishes the plugin.
- Release candidates (`vX.Y.Z-rcN`) come from the `cut-prerelease` workflow.

## Related repositories

- [plugin-aws-apigateway-policies](https://github.com/compliance-framework/plugin-aws-apigateway-policies)
