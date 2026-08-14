# Data, Analytics, and AI: secure operation patterns

## Services covered

- **athena**: serverless SQL over S3; queries are jobs (executions), results land in an S3 output location.
- **glue**: data catalog (databases, tables, partitions), ETL jobs, crawlers, interactive sessions, schema registry.
- **lakeformation**: permission layer over the Glue catalog; grants, LF-tags, transactions, temporary credentials.
- **emr / emr-serverless / emr-containers**: managed Spark and Hadoop clusters, serverless applications, EKS job runs.
- **dms**: database migration and continuous replication (instances, endpoints, tasks, serverless configs).
- **opensearch / es / opensearchserverless**: search domains and serverless collections; es is the legacy API.
- **quicksight**: BI dashboards, datasets, ingestions; permission and embed-URL surface is large and sensitive.
- **sagemaker**: notebooks, training, endpoints, pipelines, model registry; the largest API in this domain.
- **bedrock / bedrock-runtime / bedrock-agent / bedrock-agentcore**: foundation models, inference, agents, knowledge bases, gateways, credential providers.
- **kendra / qbusiness / qapps**: enterprise search and assistant applications over corporate content.
- **datazone**: data governance portal; domains, projects, subscriptions, grants.
- **comprehend / rekognition / transcribe / translate / textract / polly**: per-call and batch ML inference services.
- **personalize / forecast / frauddetector / lex**: trained-model services with campaign or bot serving layers.

Long tail: appflow, cleanrooms, cleanroomsml, comprehendmedical, databrew, dataexchange, datapipeline, datasync, entityresolution, geo-maps, geo-places, geo-routes, healthlake, iotanalytics, kendra-ranking, location, medical-imaging, mwaa, omics, sagemaker-geospatial, and the per-service runtime APIs (bedrock-agent-runtime, lex-runtime, personalize-runtime, sagemaker-runtime and siblings, which invoke rather than manage).

## Querying safely

Always bound reads: server-side filters first, then `--query` for projection, then `--max-items` as a hard cap. Never dump a whole catalog or a full execution history.

```bash
# Athena: check a single query execution, not the full history
aws athena get-query-execution --query-execution-id <id> \
  --query 'QueryExecution.{State:Status.State,Reason:Status.StateChangeReason,Scanned:Statistics.DataScannedInBytes}'
aws athena list-query-executions --work-group primary --max-items 20

# Glue: target one database, project only what you need
aws glue get-tables --database-name sales --max-items 50 \
  --query 'TableList[].{Name:Name,Loc:StorageDescriptor.Location,Updated:UpdateTime}'
aws glue get-job-runs --job-name nightly-etl --max-items 5 \
  --query 'JobRuns[].{Id:Id,State:JobRunState,Started:StartedOn,Error:ErrorMessage}'
aws glue get-crawler --name sales-crawler --query 'Crawler.{State:State,Last:LastCrawl}'

# Lake Formation: scope permission listings to one principal or one resource
aws lakeformation list-permissions --principal DataLakePrincipalIdentifier=<role-arn> --max-items 50

# EMR: filter server-side by state, never list all clusters unbounded
aws emr list-clusters --cluster-states RUNNING WAITING --max-items 20 \
  --query 'Clusters[].{Id:Id,Name:Name,State:Status.State}'
aws emr describe-cluster --cluster-id j-XXXX --query 'Cluster.{State:Status.State,Apps:Applications}'

# DMS: use Name/Values filters, they are server-side
aws dms describe-replication-tasks \
  --filters Name=replication-task-id,Values=<task-id> \
  --query 'ReplicationTasks[].{Status:Status,Progress:ReplicationTaskStats.FullLoadProgressPercent}'

# OpenSearch: one domain at a time
aws opensearch describe-domain --domain-name logs \
  --query 'DomainStatus.{Processing:Processing,Endpoint:Endpoints,EngineVersion:EngineVersion}'

# QuickSight: account-scoped calls need --aws-account-id; cap listings
aws quicksight list-dashboards --aws-account-id <acct> --max-items 25 \
  --query 'DashboardSummaryList[].{Id:DashboardId,Name:Name}'
aws quicksight describe-ingestion --aws-account-id <acct> --data-set-id <id> --ingestion-id <id> \
  --query 'Ingestion.{Status:IngestionStatus,Rows:RowInfo}'

# SageMaker: server-side filters exist on most list calls, use them
aws sagemaker list-training-jobs --status-equals InProgress --max-items 20 \
  --query 'TrainingJobSummaries[].{Name:TrainingJobName,Status:TrainingJobStatus}'
aws sagemaker list-endpoints --status-equals InService --max-items 20
aws sagemaker describe-endpoint --endpoint-name <name> \
  --query '{Status:EndpointStatus,Reason:FailureReason}'

# Bedrock: filter model listings by provider or modality
aws bedrock list-foundation-models --by-provider anthropic \
  --query 'modelSummaries[].{Id:modelId,Streaming:responseStreamingSupported}'
```

Reads that emit credentials are not passive: `lakeformation get-temporary-glue-*-credentials`, `emr get-cluster-session-credentials`, `datazone get-environment-credentials`, `bedrock-agentcore get-resource-*` and `get-workload-access-token*`, and every presigned or embed URL call (`sagemaker create-presigned-*`, `quicksight get-*-embed-url`, `generate-embed-url-*`, `mwaa create-cli-token`, `create-web-login-token`, `athena create-presigned-notebook-url`). Treat their output as secrets: never log it, never paste it into tickets, let it expire rather than revoking manually.

## Mutating safely

Almost nothing in this domain supports a dry run (the one exception is OpenSearch domain config, below). Substitutes, in order of preference:

- **Validate before publish**: `glue` job updates accept a full `--job-update` JSON, review it locally first; `databrew` and `emr` accept configuration JSON files, lint them with `python -m json.tool` before submitting.
- **Draft, then promote**: Bedrock agents and Lex bots have an explicit build step (`prepare-agent`, `build-bot-locale`) against a DRAFT version; test the draft alias before creating a version and moving a production alias. QuickSight dashboards version on each `update-dashboard`; publish is a separate `update-dashboard-published-version` call, so verify the new version before flipping it.
- **Blue/green built in**: `sagemaker update-endpoint` deploys a new endpoint config alongside the old one; create a new `endpoint-config` rather than mutating in place, and keep the previous config until the endpoint returns to `InService`.
- **Real dry run where it exists**: `aws opensearch update-domain-config --domain-name X ... --dry-run --dry-run-mode Verbose` validates the change and reports whether it forces a blue/green deployment, without applying anything. Always run it before the real config change.
- **One target per command**: avoid `batch-*` mutations (`glue batch-delete-table`, `kendra batch-delete-document`, `lakeformation batch-grant-permissions`) unless the item list was generated and reviewed in the same change record. Prefer the singular form in interactive work.

Tag at creation time. Syntax varies by service; the three common shapes:

```bash
# Key=Value list (athena, emr, dms, opensearch)
aws emr create-cluster ... --tags team=data purpose=nightly-etl
aws athena start-query-execution ... # tag the workgroup, not the query

# --tags KeyValuePairs (sagemaker, kendra, quicksight uses --tags Key=,Value=)
aws sagemaker create-training-job ... --tags Key=team,Value=data Key=purpose,Value=model-v3
aws quicksight create-dashboard ... --tags Key=team,Value=bi

# map form (glue, lakeformation, bedrock, datazone)
aws glue create-job ... --tags '{"team":"data","purpose":"nightly-etl"}'
aws bedrock create-model-customization-job ... --job-tags '[{"key":"team","value":"ml"}]'
```

Permission mutations are the highest-risk writes in this domain. `lakeformation grant-permissions`, every `quicksight update-*-permissions`, `qbusiness associate-permission`, and every `put-resource-policy` or `put-policy` variant change who can read data. Before any of these: read back the current policy or grant list, write the intended diff into the change record, apply, then read back again. Never grant to a wildcard principal, and treat any principal outside the account as a cross-account exposure requiring explicit sign-off.

## Destructive traps

| Command                                                             | Why dangerous                                                                                                  | Safe procedure                                                                                                                                                   |
| ------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `emr terminate-job-flows`                                           | Kills entire clusters including running steps; accepts multiple IDs                                            | One cluster ID per call; `describe-cluster` first to confirm no active steps; check termination protection is intentional before `--termination-protected false` |
| `dms stop-replication-task` / `stop-replication`                    | Halts live CDC; depending on position, resume may require a full reload                                        | Confirm task type and CDC position with `describe-replication-tasks` first; record the checkpoint; coordinate with consumers of the target                       |
| `dms reload-tables` / `reload-replication-tables`                   | Truncates target tables and re-copies from source; target data is dropped first                                | Only against a RUNNING task, one table list per change record, confirm target consumers can tolerate the gap                                                     |
| `dms reboot-replication-instance`                                   | Interrupts every task on the instance                                                                          | List tasks on the instance first; prefer a maintenance window; never `--force-failover` casually                                                                 |
| `glue batch-delete-table` / `delete-database`                       | `delete-database` cascades: all tables, partitions, and functions in it are removed from the catalog           | Enumerate contents first (`get-tables --max-items`), export the catalog definitions to a file, delete one object per command                                     |
| `lakeformation revoke-permissions` / `deregister-resource`          | Silently breaks every downstream query relying on the grant or registered location                             | `list-permissions` scoped to the resource first; capture current grants in the change record; revoke one principal at a time                                     |
| `quicksight delete-data-set` / `delete-data-source`                 | Dashboards and analyses depending on it break immediately; SPICE data is gone                                  | `list-dashboards` and search for dependencies first; export definitions (`describe-data-set`) before deleting                                                    |
| `quicksight update-public-sharing-settings`                         | Can make dashboards reachable without authentication                                                           | Treat as an exposure change: written approval, read back the setting after, audit which dashboards have public sharing enabled                                   |
| `sagemaker delete-endpoint`                                         | Live inference traffic fails instantly; endpoint config and model objects survive but the serving path is gone | Confirm no production traffic (CloudWatch invocations metric), delete config and model only after the endpoint itself is confirmed gone                          |
| `kendra clear-query-suggestions`                                    | Irreversibly deletes all learned suggestions for an index                                                      | Confirm index ID twice; there is no export; expect days to weeks for suggestions to re-learn                                                                     |
| `opensearch delete-domain` / `es delete-elasticsearch-domain`       | Whole domain and all indices are destroyed; no recycle bin                                                     | Take and verify a manual snapshot first; confirm automated snapshot repo is external if data must survive                                                        |
| `athena delete-work-group`                                          | With `--recursive-delete-option` it deletes saved queries and named queries in the workgroup                   | Never pass the recursive flag on first attempt; list named queries first                                                                                         |
| `personalize stop-recommender` / `rekognition stop-project-version` | Stops a live serving model; client calls fail until restarted (restart takes minutes to hours)                 | Confirm no callers via metrics; schedule the stop; restart procedure documented before stopping                                                                  |

## Waiters and timing

Waiter wall-clock budget is delay times attempts. Always pair a waiter with a timeout expectation; if the waiter exhausts attempts, stop and investigate rather than looping again blindly.

| Service                   | Waiter                                               | Cadence           | Max wait |
| ------------------------- | ---------------------------------------------------- | ----------------- | -------- |
| emr                       | cluster-running / cluster-terminated                 | 30s x 60          | 30 min   |
| emr                       | step-complete                                        | 30s x 60          | 30 min   |
| dms                       | replication-instance-available                       | 60s x 60          | 60 min   |
| dms                       | replication-task-ready / -running / -stopped         | 15s x 60          | 15 min   |
| dms                       | test-connection-succeeds                             | 5s x 60           | 5 min    |
| sagemaker                 | endpoint-in-service                                  | 30s x 120         | 60 min   |
| sagemaker                 | endpoint-deleted                                     | 30s x 60          | 30 min   |
| sagemaker                 | training-job-completed-or-stopped                    | 120s x 180        | 6 h      |
| sagemaker                 | processing/transform-job-completed-or-stopped        | 60s x 60          | 60 min   |
| sagemaker                 | notebook-instance-in-service / -stopped / -deleted   | 30s x 60          | 30 min   |
| lexv2-models              | bot-locale-built, bot-version-available and siblings | 10s x 35          | ~6 min   |
| rekognition               | project-version-running                              | 30s x 40          | 20 min   |
| rekognition               | project-version-training-completed                   | 120s x 360        | 12 h     |
| healthlake                | fhir-datastore-active / import/export jobs           | 60-120s x 360-720 | 6-24 h   |
| omics                     | run-completed, store and job waiters                 | 30s x 20          | 10 min   |
| bedrock-agentcore-control | policy and memory waiters                            | 2s x 60           | 2 min    |

Usage: `aws sagemaker wait endpoint-in-service --endpoint-name <name>`.

No waiter exists for large parts of this domain; poll the status field with a bounded loop (fixed sleep, fixed max iterations, then stop):

- **athena**: poll `get-query-execution` on `Status.State` until SUCCEEDED/FAILED/CANCELLED; 5s interval, cap at 60 iterations for interactive queries.
- **glue**: poll `get-job-run --run-id` on `JobRunState`; crawlers via `get-crawler` on `State` returning to READY; 30s interval.
- **quicksight**: poll `describe-ingestion` on `IngestionStatus`; 15s interval.
- **bedrock**: poll `get-model-customization-job` on `status`; minutes-scale, 60s interval.
- **emr-serverless**: poll `get-job-run` on `state`; 30s interval.
- **datasync**: poll `describe-task-execution` on `Status`; 30s interval.
- **transcribe / comprehend / textract**: poll the job describe call on the job status field; 30s interval, respect service throttling.

## Verification after change

Prove every mutation landed with a scoped read-back, and record the output.

```bash
# Glue job updated
aws glue get-job --job-name nightly-etl --query 'Job.{Cmd:Command,Args:DefaultArguments,Ver:GlueVersion}'

# Lake Formation grant applied (or revoked)
aws lakeformation list-permissions \
  --resource '{"Table":{"DatabaseName":"sales","Name":"orders"}}' --max-items 50

# EMR cluster state after terminate
aws emr describe-cluster --cluster-id j-XXXX --query 'Cluster.Status.{State:State,Reason:StateChangeReason}'

# DMS task after stop/resume
aws dms describe-replication-tasks --filters Name=replication-task-id,Values=<id> \
  --query 'ReplicationTasks[].{Status:Status,StopReason:StopReason,Checkpoint:RecoveryCheckpoint}'

# SageMaker endpoint after update (config name proves which version serves)
aws sagemaker describe-endpoint --endpoint-name <name> \
  --query '{Status:EndpointStatus,Config:EndpointConfigName}'

# QuickSight permissions after a permissions update: read the full grant list back
aws quicksight describe-dashboard-permissions --aws-account-id <acct> --dashboard-id <id> \
  --query 'Permissions[].{Principal:Principal,Actions:Actions}'
aws quicksight describe-account-settings --aws-account-id <acct> \
  --query 'AccountSettings.PublicSharingEnabled'

# OpenSearch config change: Processing=false means the change finished applying
aws opensearch describe-domain --domain-name logs --query 'DomainStatus.{Processing:Processing,Change:ChangeProgressDetails}'

# Resource policy writes: always read the policy back verbatim
aws glue get-resource-policy --query 'PolicyInJson'
aws lexv2-models describe-resource-policy --resource-arn <arn>
aws sagemaker get-model-package-group-policy --model-package-group-name <name>

# Bedrock agent prepared and alias routing
aws bedrock-agent get-agent --agent-id <id> --query 'agent.{Status:agentStatus,Prepared:preparedAt}'
aws bedrock-agent get-agent-alias --agent-id <id> --agent-alias-id <id> \
  --query 'agentAlias.{Status:agentAliasStatus,Routing:routingConfiguration}'
```

For deletes, verify by absence: rerun the describe call and expect the service's not-found error (`EntityNotFoundException` for Glue, `ResourceNotFoundException` for most others). A list call that no longer contains the resource is weaker evidence than a describe that errors; prefer the describe.

For any permission or policy change, verification is two-sided: read the policy back, and where feasible confirm the affected principal's effective access changed (a scoped test query for grants, an expected AccessDenied for revocations).
