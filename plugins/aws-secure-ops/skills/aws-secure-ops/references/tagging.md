# Tagging: intent that travels with the resource

A tag set is the only part of a resource that speaks for you when you are not
in the room. Auditors, cost tools, cleanup jobs, and automated trail analysis
all read tags before they read anything else. An untagged resource is an
anonymous resource; an anonymous resource created by a privileged session is a
finding. A cryptic tag is worse than none: a resource labeled with an opaque
test slug and no context reads as undocumented automation.

## The canonical tag set

Apply at creation time, on every resource that supports tags:

| Key           | Value                                                       | Why                                                     |
| ------------- | ----------------------------------------------------------- | ------------------------------------------------------- |
| `Name`        | Human-readable name; `TEST-` prefix for temporary resources | The first thing every console and report shows          |
| `environment` | `production`, `staging`, `development`, ...                 | Blast-radius triage and org policy                      |
| `team`        | Owning team identifier                                      | Routing: who to ask before touching it                  |
| `owner`       | Corporate identity of the accountable human                 | Accountability; never a tool or automation name         |
| `purpose`     | One professional sentence: what + why + authorization       | The tag an auditor actually reads                       |
| `managed-by`  | `cloudformation`, `terraform`, `manual-operation`, ...      | Tells responders whether hand-edits will be overwritten |
| `ticket`      | Issue/PR/change reference, when one exists                  | Links the resource to its paper trail                   |
| `expires`     | ISO date, mandatory for temporary/test resources            | Makes cleanup verifiable and abandonment visible        |

Merge in any `required_tags` from the local policy file; organizational
required tags are non-negotiable minimums, not replacements for the set above.

## Writing the purpose tag

State what the resource is for, why it exists now, and under what authority.
Write it for a reviewer who has none of your context.

Good:

- `purpose=Controlled restore validation of the database backup chain; coordinated with the platform owner; temporary, deleted same day`
- `purpose=Egress allowlist for the corporate boundary, per the network team's canonical list`
- `purpose=Canary volume for backup-freshness alerting test; announced to the owning team; expires 2026-01-15`

Bad, and why:

- `purpose=test` (which test, whose, until when?)
- `purpose=tmp-fix` (undocumented change, invites rollback by a stranger)
- `injection-detection-test` as a bare Name with no purpose tag (reads as
  unauthorized security tooling, precisely the thing trail analysis hunts)

Never include credentials, hostnames of internal systems, or people's personal
data in tag values; tags are broadly readable metadata, not a secrets channel.

## Per-service syntax

Tag at creation wherever the API allows it; a resource that exists untagged
even for a minute is a gap in the record.

```bash
# Most modern APIs: --tags Key=,Value= list
aws elbv2 add-tags --resource-arns <arn> --tags Key=owner,Value=<operator>
aws secretsmanager create-secret --name <n> --tags Key=purpose,Value="..." ...

# EC2 at creation: --tag-specifications per resource type
aws ec2 create-volume ... --tag-specifications \
  'ResourceType=volume,Tags=[{Key=Name,Value=TEST-restore-check},{Key=purpose,Value="..."},{Key=expires,Value=2026-01-15}]'

# EC2 after creation
aws ec2 create-tags --resources <id> --tags Key=owner,Value=<operator>

# S3 buckets: a TagSet document (replaces the whole set, read-modify-write!)
aws s3api get-bucket-tagging --bucket <b>   # read first, PutBucketTagging overwrites
aws s3api put-bucket-tagging --bucket <b> --tagging 'TagSet=[{Key=owner,Value=<operator>}]'

# RDS
aws rds add-tags-to-resource --resource-name <arn> --tags Key=purpose,Value="..."

# Lambda / many serverless APIs: a map, not a list
aws lambda tag-resource --resource <arn> --tags owner=<operator>,purpose="..."

# CloudFormation: stack-level tags PROPAGATE to every supported resource
aws cloudformation create-change-set ... \
  --tags Key=environment,Value=production Key=team,Value=<team> Key=owner,Value=<operator>

# Retrofit across services (use sparingly, it is a mutation per resource)
aws resourcegroupstaggingapi tag-resources --resource-arn-list <arn> \
  --tags environment=production,owner=<operator>
```

The CloudFormation path is the highest-leverage one: passing `--tags` on the
deploy command tags the stack and every propagating resource in it without
touching templates.

## Temporary and test resources

- `Name` starts with `TEST-`, `expires` is set, `purpose` names the test, the
  authorization, and the cleanup plan.
- Announce controlled tests to the owning or reviewing team before running.
- Delete individually, verify deletion, and confirm zero residue (volumes,
  snapshots, ENIs, log groups left behind).
- Never create several test resources in a rapid burst; one canary usually
  suffices, and deliberate pacing costs nothing.

## Auditing your own tags

```bash
# What is untagged or under-tagged in this account (bounded, read-only)
aws resourcegroupstaggingapi get-resources --resources-per-page 50 \
  --query "ResourceTagMappingList[?length(Tags)==\`0\`].ResourceARN"

# Everything carrying a TEST- name past its expiry is a cleanup debt
aws resourcegroupstaggingapi get-resources --tag-filters Key=expires --resources-per-page 50
```
