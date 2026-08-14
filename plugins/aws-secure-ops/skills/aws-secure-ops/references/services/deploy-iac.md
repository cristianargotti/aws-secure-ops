# Deployment and infrastructure-as-code: secure operation patterns

Scope: CloudFormation, Cloud Control, SSM (and the ssm-* family), the Code* developer
tooling suite, AWS Config, AppConfig, Service Catalog, Proton, Application Auto Scaling,
Control Tower, FIS, and the migration and resilience services (MGN, DRS, Migration Hub,
Resilience Hub).

## Services covered

- `cloudformation`: stack, stack set, and change-set lifecycle; the primary IaC engine.
- `cloudcontrol`: uniform CRUD over CloudFormation resource types (async request model).
- `ssm`: parameters, documents, Run Command, sessions, patching, maintenance windows.
- `codebuild` / `codedeploy` / `codepipeline` / `codecommit`: build, deploy, pipeline, and repository lifecycle.
- `configservice`: recorders, rules, conformance packs, aggregators (compliance evidence chain).
- `appconfig` / `appconfigdata`: staged application configuration deployments with rollback.
- `servicecatalog` (+ `servicecatalog-appregistry`): governed product portfolios and provisioned products.
- `proton`: environment and service templates with managed deployments.
- `application-autoscaling`: scaling targets, policies, scheduled actions for non-EC2 targets.
- `controltower`: landing zone and enabled controls (account-wide blast radius).
- `fis`: fault injection experiments (deliberately disruptive by design).
- `mgn` / `drs`: server migration and disaster recovery replication.
- Long tail, same review rules apply: `amplify`, `amplifybackend`, `amplifyuibuilder`,
  `auditmanager`, `codecatalyst`, `codeconnections`, `codestar-connections`,
  `codestar-notifications`, `codeguru-reviewer`, `codeguru-security`, `codeguruprofiler`,
  `controlcatalog`, `launch-wizard`, `license-manager` (+ linux/user subscriptions),
  `mgh`, `migration-hub-refactor-spaces`, `migrationhub-config`, `migrationhuborchestrator`,
  `migrationhubstrategy`, `resiliencehub`, `ssm-contacts`, `ssm-guiconnect`,
  `ssm-incidents`, `ssm-quicksetup`, `ssm-sap`.

## Querying safely

Always bound reads: name the resource, filter server side, project with `--query`, and cap
pages with `--max-items`. Never dump a whole account surface to find one object.

CloudFormation:

```bash
aws cloudformation describe-stacks --stack-name my-stack \
  --query 'Stacks[0].{Status:StackStatus,Updated:LastUpdatedTime}'
aws cloudformation list-stacks \
  --stack-status-filter UPDATE_COMPLETE CREATE_COMPLETE --max-items 50
aws cloudformation describe-stack-events --stack-name my-stack --max-items 20 \
  --query 'StackEvents[].{T:Timestamp,R:LogicalResourceId,S:ResourceStatus,Why:ResourceStatusReason}'
aws cloudformation get-template --stack-name my-stack --template-stage Original
```

SSM: prefer path-scoped and filtered parameter reads. `get-parameter` with
`--with-decryption` emits secret material: treat output as sensitive, never log it.

```bash
aws ssm get-parameter --name /app/prod/db_host --query 'Parameter.Value' --output text
aws ssm get-parameters-by-path --path /app/prod/ --recursive --max-items 50 \
  --query 'Parameters[].{Name:Name,Type:Type,Ver:Version}'   # names only, no --with-decryption
aws ssm describe-instance-information \
  --filters Key=PingStatus,Values=Online --max-items 50 \
  --query 'InstanceInformationList[].{Id:InstanceId,Ping:PingStatus,Agent:AgentVersion}'
aws ssm list-command-invocations --command-id <id> --details \
  --query 'CommandInvocations[].{Id:InstanceId,Status:Status}'
```

Code* suite:

```bash
aws codepipeline get-pipeline-state --name my-pipeline \
  --query 'stageStates[].{Stage:stageName,Status:latestExecution.status}'
aws codebuild batch-get-builds --ids <build-id> \
  --query 'builds[].{Status:buildStatus,Phase:currentPhase}'
aws codedeploy get-deployment --deployment-id <id> \
  --query 'deploymentInfo.{Status:status,Overview:deploymentOverview}'
aws codecommit get-branch --repository-name repo --branch-name main
```

Config and AppConfig:

```bash
aws configservice describe-configuration-recorder-status
aws configservice describe-compliance-by-config-rule \
  --compliance-types NON_COMPLIANT --max-items 25
aws appconfig get-deployment --application-id X --environment-id Y --deployment-number N \
  --query '{State:State,Pct:PercentageComplete,Event:EventLog[0].Description}'
```

Service Catalog and Cloud Control:

```bash
aws servicecatalog search-provisioned-products \
  --filters 'SearchQuery=["name:my-product"]' --page-size 20 \
  --query 'ProvisionedProducts[].{Name:Name,Status:Status}'
aws cloudcontrol get-resource --type-name AWS::Logs::LogGroup --identifier my-group
```

## Mutating safely

General rules: one target per command, tag at creation time, prefer a staged plan over a
direct mutation, and state the change purpose in the audit trail before executing.

CloudFormation, always change sets for existing stacks. Never `update-stack` directly on
anything shared or production:

```bash
aws cloudformation validate-template --template-body file://tpl.yml     # offline-safe lint
aws cloudformation create-change-set --stack-name my-stack \
  --change-set-name cs-2026-08-14-fix-alarm --template-body file://tpl.yml \
  --capabilities CAPABILITY_NAMED_IAM \
  --tags Key=owner,Value=platform Key=purpose,Value=alarm-threshold-fix
aws cloudformation describe-change-set --stack-name my-stack \
  --change-set-name cs-2026-08-14-fix-alarm \
  --query 'Changes[].ResourceChange.{Action:Action,Res:LogicalResourceId,Replace:Replacement}'
# Review every Action and Replacement=True before executing:
aws cloudformation execute-change-set --stack-name my-stack \
  --change-set-name cs-2026-08-14-fix-alarm
```

Replacement=True means delete-and-recreate of that resource: treat the change set as
destructive and require confirmation. Protect long-lived stacks up front:

```bash
aws cloudformation update-termination-protection --stack-name my-stack \
  --enable-termination-protection
aws cloudformation set-stack-policy --stack-name my-stack \
  --stack-policy-body file://deny-replace-db.json
```

For new stacks, pass `--on-failure DELETE` (or `ROLLBACK`) explicitly and tag the stack;
tags propagate to created resources.

Cloud Control is asynchronous: every mutation returns a `RequestToken`. Submit one
resource per call and track the token to completion:

```bash
aws cloudcontrol update-resource --type-name AWS::Logs::LogGroup \
  --identifier my-group --patch-document '[{"op":"replace","path":"/RetentionInDays","value":30}]'
aws cloudcontrol get-resource-request-status --request-token <token>
```

SSM parameters: `put-parameter` with an inline value places the secret in shell history
and CloudTrail-adjacent tooling. Load values from a file descriptor, use
`--type SecureString`, and never `--overwrite` without first reading the current version:

```bash
aws ssm put-parameter --name /app/prod/api_key --type SecureString \
  --value "file:///dev/fd/3" --tags Key=owner,Value=platform 3<secret.txt
```

SSM Run Command: pin the document version, target explicitly, and bound concurrency:

```bash
aws ssm send-command --document-name AWS-RunShellScript --document-version '$LATEST' \
  --targets Key=InstanceIds,Values=i-0abc123 \
  --max-concurrency 1 --max-errors 0 \
  --parameters commands='["systemctl status nginx"]' \
  --comment "purpose: verify nginx unit state"
```

AppConfig deploys are natively staged: pick a deployment strategy with bake time and
growth factor rather than an all-at-once push; the service rolls back on alarm.

CodeDeploy and CodePipeline: start one deployment or one execution per command, never
loop over targets. `codepipeline put-approval-result` releases a gated stage: it is a
human decision, record the reviewer and rationale in `--result` summary.

Application Auto Scaling `put-scaling-policy` and `register-scalable-target` overwrite
existing settings silently: read the current policy first, then write.

## Destructive traps

| Command                                                                       | Why dangerous                                                                | Safe procedure                                                                                                          |
| ----------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `cloudformation delete-stack`                                                 | Deletes every resource in the stack; data resources go with it               | Check termination protection, list resources first, use `--retain-resources` for stateful members, snapshot data stores |
| `cloudformation execute-change-set` with Replacement=True                     | Replaces resources (delete + recreate), losing state and endpoints           | Read `describe-change-set` output line by line; abort on unexpected Replace                                             |
| `cloudformation rollback-stack` / `continue-update-rollback`                  | Reverts to last known state; resources created since are removed             | Diff current vs. previous template, confirm which resources disappear                                                   |
| `cloudformation delete-stack-instances`                                       | Removes stacks across accounts and regions in one call                       | Use `--no-retain-stacks` only deliberately; start with one account and region                                           |
| `configservice stop-configuration-recorder` / `delete-configuration-recorder` | Halts the compliance recording chain; gaps are unrecoverable evidence loss   | Require explicit approval, record the window, restart and verify immediately after                                      |
| `configservice delete-config-rule` / `delete-conformance-pack`                | Removes compliance controls and their evaluation history                     | Export evaluation results first, confirm rule is not organization-managed                                               |
| `ssm delete-parameter(s)`                                                     | Parameter history is gone; dependent apps fail at next read                  | `get-parameter-history` export first; delete one name, never a wildcard-derived batch                                   |
| `ssm terminate-session`                                                       | Kills a live operator session mid-work                                       | Confirm session owner via `describe-sessions` before terminating                                                        |
| `ssm deregister-managed-instance`                                             | Node loses SSM management, and with SSM-only access there is no other way in | Verify the instance is decommissioned first; this can lock you out permanently                                          |
| `ssm modify-document-permission --account-ids all`                            | Makes the document public to every AWS account                               | Share to explicit account IDs only; audit with `describe-document-permission`                                           |
| `codedeploy skip-wait-time-for-instance-termination`                          | Immediately terminates the original fleet, removing the rollback path        | Verify replacement environment health first; prefer letting the wait time expire                                        |
| `codecommit delete-repository`                                                | Repository and all refs are unrecoverable unless mirrored                    | Confirm an up-to-date mirror or clone exists; require explicit confirmation                                             |
| `servicecatalog terminate-provisioned-product`                                | Tears down the underlying stack and all its resources                        | Review the provisioned product's outputs and record set; snapshot stateful parts                                        |
| `controltower delete-landing-zone` / `disable-control`                        | Account-governance-wide blast radius                                         | Treat as an organizational change with formal approval, never routine                                                   |
| `fis start-experiment`                                                        | Injects real faults into live workloads by design                            | Verify target selectors and stop conditions (alarms) before starting                                                    |
| `mgn terminate-target-instances` / `drs terminate-recovery-instances`         | Terminates launched EC2 instances                                            | List the exact instance IDs first; confirm they are test, not cutover, instances                                        |
| `mgn finalize-cutover` / `drs disconnect-source-server`                       | Stops replication; the recovery point stream ends                            | Confirm cutover acceptance criteria met and a final snapshot exists                                                     |
| `application-autoscaling deregister-scalable-target`                          | Deletes all scaling policies and scheduled actions for the target            | Export current policies first; expect capacity to freeze at current level                                               |
| `appconfig stop-deployment`                                                   | Rolls back an in-flight configuration deployment                             | Intentional rollback tool; confirm which version clients revert to                                                      |

Exposure boundary changes that force confirmation even though nothing is deleted:
`put-resource-policy` (codebuild, ssm, ssm-incidents, migration-hub-refactor-spaces),
`configservice put-aggregation-authorization` (cross-account data collection),
`servicecatalog create-portfolio-share` and `update-portfolio-share` (cross-account and
organization shares), `ssm-contacts put-contact-policy` (RAM share),
`codeguruprofiler put-permission`, `license-manager create-grant`,
`auditmanager start-assessment-framework-share`, `ssm-sap put-resource-permission`.

Credential emitters, capture output only into a secure sink:
`ssm get-parameter --with-decryption`, `ssm get-access-token`,
`codecatalyst create-access-token`, `license-manager create-token` and
`get-access-token`, `amplifybackend create-token` and `get-token`,
`codebuild import-source-credentials` (secret travels in the argument list).

## Waiters and timing

Use waiters instead of sleep loops. Delay x attempts gives the maximum wait.

| Service        | Waiter                                              | Delay x attempts | Max wait | Polls                       |
| -------------- | --------------------------------------------------- | ---------------- | -------- | --------------------------- |
| cloudformation | stack-create-complete                               | 30s x 120        | 60 min   | describe-stacks             |
| cloudformation | stack-update-complete                               | 30s x 120        | 60 min   | describe-stacks             |
| cloudformation | stack-delete-complete                               | 30s x 120        | 60 min   | describe-stacks             |
| cloudformation | stack-rollback-complete                             | 30s x 120        | 60 min   | describe-stacks             |
| cloudformation | change-set-create-complete                          | 30s x 120        | 60 min   | describe-change-set         |
| cloudformation | stack-import-complete                               | 30s x 120        | 60 min   | describe-stacks             |
| cloudformation | type-registration-complete                          | 30s x 120        | 60 min   | describe-type-registration  |
| cloudcontrol   | resource-request-success                            | 5s x 24          | 2 min    | get-resource-request-status |
| codedeploy     | deployment-successful                               | 15s x 120        | 30 min   | get-deployment              |
| ssm            | command-executed                                    | 5s x 20          | 100 s    | get-command-invocation      |
| appconfig      | deployment-complete                                 | 30s x 999        | ~8.3 h   | get-deployment              |
| appconfig      | environment-ready-for-deployment                    | 30s x 999        | ~8.3 h   | get-environment             |
| proton         | environment-deployed                                | 5s x 999         | ~83 min  | get-environment             |
| proton         | service-created / service-updated / service-deleted | 5s x 999         | ~83 min  | get-service                 |
| proton         | service-pipeline-deployed                           | 10s x 360        | 60 min   | get-service                 |

```bash
aws cloudformation wait stack-update-complete --stack-name my-stack
aws ssm wait command-executed --command-id <id> --instance-id i-0abc123
```

Caveats: `ssm command-executed` gives only 100 seconds, so for long Run Command scripts
poll `get-command-invocation` yourself with a bounded loop (fixed attempt count, explicit
timeout, never `while true`). The 999-attempt waiters (appconfig, proton) effectively
wait for hours: wrap them in `timeout` when a shorter budget applies.

No waiter exists for: CodeBuild builds (poll `batch-get-builds` on `buildStatus`),
CodePipeline executions (poll `get-pipeline-execution` or `get-pipeline-state`),
Service Catalog provisioning (poll `describe-record` on `RecordDetail.Status`),
Config rule evaluations (poll `describe-config-rule-evaluation-status`),
MGN/DRS jobs (poll `describe-jobs` / `describe-job-log-items`),
FIS experiments (poll `get-experiment` on `state.status`). Bound every loop: a fixed
number of attempts with a fixed sleep, then fail loudly.

## Verification after change

Prove the mutation landed with a read-back, not with the mutation's exit code.

```bash
# CloudFormation: status, then drift
aws cloudformation describe-stacks --stack-name my-stack \
  --query 'Stacks[0].{S:StackStatus,Reason:StackStatusReason}'
aws cloudformation detect-stack-drift --stack-name my-stack
aws cloudformation describe-stack-drift-detection-status --stack-drift-detection-id <id>

# Change executed as planned: compare applied template
aws cloudformation get-template --stack-name my-stack --template-stage Processed

# SSM parameter: version advanced, correct type, no unintended overwrite
aws ssm get-parameter --name /app/prod/db_host \
  --query 'Parameter.{Ver:Version,Type:Type,Modified:LastModifiedDate}'

# SSM Run Command: per-instance rc and output
aws ssm get-command-invocation --command-id <id> --instance-id i-0abc123 \
  --query '{Status:Status,RC:ResponseCode,Out:StandardOutputContent}'

# CodeDeploy: all instances succeeded, none skipped
aws codedeploy get-deployment --deployment-id <id> \
  --query 'deploymentInfo.deploymentOverview'

# CodePipeline: stage landed the new revision
aws codepipeline get-pipeline-state --name my-pipeline \
  --query 'stageStates[?stageName==`Deploy`].latestExecution.status'

# Config: recorder running again after any recorder work
aws configservice describe-configuration-recorder-status \
  --query 'ConfigurationRecordersStatus[].{Name:name,Recording:recording,Status:lastStatus}'

# AppConfig: deployment baked and complete
aws appconfig get-deployment --application-id X --environment-id Y \
  --deployment-number N --query '{State:State,Pct:PercentageComplete}'

# Service Catalog: record succeeded
aws servicecatalog describe-record --id <record-id> \
  --query 'RecordDetail.{Status:Status,Errors:RecordErrors}'

# Cloud Control: request success and resulting model
aws cloudcontrol get-resource-request-status --request-token <token>
aws cloudcontrol get-resource --type-name <type> --identifier <id>
```

After any policy or share mutation, read the boundary back: `get-resource-policies`
(ssm), `describe-document-permission` (ssm), `describe-portfolio-shares`
(servicecatalog), `get-policy` (codeguruprofiler), `describe-aggregation-authorizations`
(configservice). Confirm the principal list is exactly what was intended, nothing wider.
