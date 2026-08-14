# Databases: secure operation patterns

Scope: managed database and data-store services. Control plane (provision, modify, delete
clusters and tables) and data plane (query, write, transact) are both covered. Data-plane
commands run arbitrary reads and writes against production data: treat SQL and PartiQL
payloads with the same care as infrastructure mutations.

## Services covered

- `rds`: relational instances and Aurora clusters, snapshots, replicas, proxies, blue/green deployments. The largest surface in this domain.
- `dynamodb`: tables, backups, data plane (put, query, scan, transactions), resource policies.
- `redshift`: provisioned warehouses, snapshots, datashares, reserved nodes, credentials issuance.
- `redshift-serverless`: namespaces, workgroups, recovery points, credentials issuance.
- `redshift-data` / `rds-data`: SQL-over-API data plane, no cluster CRUD but full SQL power.
- `elasticache`: Redis and Memcached clusters, replication groups, serverless caches, users.
- `docdb` / `docdb-elastic`: MongoDB-compatible clusters and elastic clusters.
- `neptune` / `neptune-graph` / `neptunedata`: graph clusters, analytics graphs, and the graph data plane (queries, loader jobs, fast reset).
- `memorydb`: durable Redis-compatible clusters, ACLs, users.
- `dsql`: distributed SQL clusters and cluster policies.
- Long tail: `dax`, `keyspaces`, `keyspacesstreams`, `dynamodbstreams`, `timestream-write`, `timestream-query`, `timestream-influxdb`.

## Querying safely

Always name the target resource and bound the output. Never dump a whole account inventory
when one identifier answers the question.

```bash
# RDS: one instance, only the fields you need
aws rds describe-db-instances --db-instance-identifier mydb \
  --query 'DBInstances[0].{Status:DBInstanceStatus,Engine:Engine,AZ:AvailabilityZone,Public:PubliclyAccessible}'

# RDS: instances of one cluster only, never the full account list
aws rds describe-db-instances --filters Name=db-cluster-id,Values=mycluster \
  --query 'DBInstances[].{Id:DBInstanceIdentifier,Status:DBInstanceStatus}'

# RDS: recent events for one source, bounded window
aws rds describe-events --source-identifier mydb --source-type db-instance --duration 60

# DynamoDB: prefer query over scan, always with a key condition and a limit
aws dynamodb query --table-name orders \
  --key-condition-expression 'pk = :p' \
  --expression-attribute-values '{":p":{"S":"tenant#42"}}' \
  --max-items 50

# DynamoDB: count without pulling items
aws dynamodb query --table-name orders --select COUNT \
  --key-condition-expression 'pk = :p' \
  --expression-attribute-values '{":p":{"S":"tenant#42"}}'

# Redshift Data API: bound every SQL read with LIMIT, then poll the statement
aws redshift-data execute-statement --workgroup-name wg --database dev \
  --sql 'select id, status from audit.events order by ts desc limit 100'
aws redshift-data describe-statement --id <statement-id>
aws redshift-data get-statement-result --id <statement-id> --max-items 100

# ElastiCache / Redshift / DocumentDB: one cluster by identifier
aws elasticache describe-cache-clusters --cache-cluster-id mycache --show-cache-node-info
aws redshift describe-clusters --cluster-identifier mywarehouse \
  --query 'Clusters[0].{Status:ClusterStatus,Public:PubliclyAccessible,Enc:Encrypted}'
aws docdb describe-db-clusters --db-cluster-identifier mydocs
```

Rules:

- `dynamodb scan` reads the entire table and bills every read unit it touches. Use it only with `--max-items`, and never as a routine health check.
- Use `--filters` and `--query` server-side or client-side projection on every describe; use `--max-items` on every paginated list.
- `rds-data execute-statement` and `redshift-data execute-statement` execute whatever SQL you pass. A "read" is only a read if the SQL is a bounded SELECT. Review the statement text before running it.

## Mutating safely

No service in this domain supports `--dry-run`. Compensate with staged flows:

1. Read the current state and record it (the describe output is your rollback reference).
2. Snapshot before any risky change to a cluster or instance:
   `aws rds create-db-snapshot --db-instance-identifier mydb --db-snapshot-identifier pre-change-YYYYMMDD`.
3. Prefer deferred application. RDS-family `modify-*` commands default to applying during
   the maintenance window; passing `--apply-immediately` is the dangerous opt-in. Omit it
   unless the change is urgent and the disruption is accepted.
4. Inspect what is queued before and after:
   `aws rds describe-pending-maintenance-actions --resource-identifier <arn>` and the
   `PendingModifiedValues` field of `describe-db-instances`.
5. For high-risk engine or parameter changes on RDS, use a blue/green deployment
   (`create-blue-green-deployment`, verify green, then `switchover-blue-green-deployment`)
   instead of mutating the live instance.
6. Parameter group changes are indirect mutations: a `modify-db-parameter-group` touches
   every instance using the group, and static parameters wait for a reboot. Check
   attachment with a describe before editing shared groups. Treat `reset-*-parameter-group`
   as a mass change, not a cleanup.
7. One target per command. Avoid `batch-*` mutation forms (`batch-modify-cluster-snapshots`,
   `batch-delete-cluster-snapshots`, `batch-write-item`) when a single-target form exists.

Tag at creation time (syntax varies by service):

```bash
aws rds create-db-instance ... --tags Key=env,Value=prod Key=owner,Value=data-platform
aws dynamodb create-table ... --tags Key=env,Value=prod Key=owner,Value=data-platform
aws elasticache create-replication-group ... --tags Key=env,Value=prod
aws redshift create-cluster ... --tags Key=env,Value=prod
aws memorydb create-cluster ... --tags Key=env,Value=prod
```

Exposure-sensitive parameters hide inside routine modify commands. These require the same
scrutiny as a policy change even though the command class is plain modify:

- `--publicly-accessible` on `rds modify-db-instance` and `redshift modify-cluster`.
- `--master-user-password` on RDS and Redshift modify commands (rotates the admin credential; the new value sits in your shell history).
- `modify-db-snapshot-attribute` / `modify-db-cluster-snapshot-attribute` with `--values-to-add all` makes a snapshot public to every AWS account.
- `redshift authorize-snapshot-access`, `authorize-data-share`, `authorize-endpoint-access`: cross-account grants.
- `rds enable-http-endpoint`: opens the Data API access path on an Aurora cluster.
- `neptune-graph create-graph` / `update-graph` accept `--public-connectivity`.

## Destructive traps

| Command                                                                                       | Why dangerous                                                                                                                  | Safe procedure                                                                                                                                                                        |
| --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `rds delete-db-instance`                                                                      | `--skip-final-snapshot` erases the last recovery point; `--delete-automated-backups` removes retained backups too              | Always pass `--final-db-snapshot-identifier`, never `--skip-final-snapshot` on data-bearing instances, verify the snapshot exists before proceeding                                   |
| `rds delete-db-cluster`                                                                       | Same final-snapshot semantics at cluster level; deletes all cluster data                                                       | `--final-db-snapshot-identifier` plus a pre-check that no instances remain attached                                                                                                   |
| `neptunedata execute-fast-reset`                                                              | Wipes ALL data in the Neptune database; the name does not say "delete"                                                         | Two-step by design (`initiateDatabaseReset` returns a token, `performDatabaseReset` consumes it); take a cluster snapshot first and confirm the endpoint targets the intended cluster |
| `neptune-graph reset-graph`                                                                   | Empties every vertex and edge from the graph                                                                                   | Snapshot with `create-graph-snapshot` first; confirm graph identifier twice                                                                                                           |
| `rds backtrack-db-cluster`                                                                    | Rewinds an Aurora MySQL cluster in place; every write after the target time is discarded                                       | Record current LSN/time, snapshot first, backtrack in small increments (backtrack forward is possible within the window)                                                              |
| `dynamodb delete-table`                                                                       | Table and all items gone; PITR history is deleted with it                                                                      | Check `--query 'Table.DeletionProtectionEnabled'` first; enable deletion protection on production tables; export or back up before deleting                                           |
| `dynamodb batch-write-item`                                                                   | Classified as a plain write but each request item can be a `DeleteRequest`                                                     | Review the request file for DeleteRequest entries before running                                                                                                                      |
| `rds-data` / `redshift-data execute-statement`                                                | Executes arbitrary SQL: DROP, TRUNCATE, DELETE without WHERE                                                                   | Read the full SQL text before execution; use a read-only DB user for investigation work                                                                                               |
| `rds promote-read-replica`                                                                    | Irreversibly severs replication and reboots the replica; you cannot reattach                                                   | Confirm the replica is meant to become standalone; take a snapshot of the source first                                                                                                |
| `elasticache test-failover`                                                                   | Performs a REAL failover on the target node group despite the word "test"                                                      | Only on non-production replication groups, or in a planned window with client retry logic verified                                                                                    |
| `rds failover-db-cluster`, `reboot-db-instance`, `stop-db-instance`, `redshift pause-cluster` | Drops live connections; stop also loses the standby and eventually auto-restarts (RDS restarts stopped instances after 7 days) | Announce a window, verify no active long transactions, use waiters to confirm return to available                                                                                     |
| `docdb-elastic stop-cluster`, `neptune-graph stop-graph`                                      | Stop a running cluster or graph; in-flight workloads fail                                                                      | Same window discipline as RDS stop; confirm no consumers before stopping                                                                                                              |
| `redshift-serverless create-reservation`, `purchase-reserved-*`                               | Commits spend for one to three years, not reversible                                                                           | Explicit human sign-off on term and quantity before running                                                                                                                           |

## Waiters and timing

Available waiters (delay x attempts = max wait):

| Service        | Waiter                                                 | Delay x attempts | Max wait |
| -------------- | ------------------------------------------------------ | ---------------- | -------- |
| rds            | db-instance-available / db-instance-deleted            | 30s x 60         | 30 min   |
| rds            | db-cluster-available / db-cluster-deleted              | 30s x 60         | 30 min   |
| rds            | db-snapshot-available / db-cluster-snapshot-available  | 30s x 60         | 30 min   |
| rds            | db-snapshot-completed                                  | 15s x 40         | 10 min   |
| docdb, neptune | db-instance-available / db-instance-deleted            | 30s x 60         | 30 min   |
| dynamodb       | table-exists / table-not-exists                        | 20s x 25         | ~8 min   |
| elasticache    | cache-cluster-available / -deleted                     | 15s x 40         | 10 min   |
| elasticache    | replication-group-available / -deleted                 | 15s x 40         | 10 min   |
| redshift       | cluster-available / cluster-deleted / cluster-restored | 60s x 30         | 30 min   |
| redshift       | snapshot-available                                     | 15s x 20         | 5 min    |
| dsql           | cluster-active / cluster-not-exists                    | 2s x 60          | 2 min    |
| neptune-graph  | graph-available, import/export-task-successful         | 60s x 480        | 8 h      |
| neptune-graph  | graph-deleted, task-cancelled                          | 60s x 60         | 1 h      |
| neptune-graph  | graph-stopped                                          | 20s x 90         | 30 min   |
| neptune-graph  | private-graph-endpoint-available / -deleted            | 10s x 180        | 30 min   |

```bash
aws rds wait db-instance-available --db-instance-identifier mydb
aws dynamodb wait table-exists --table-name orders
aws redshift wait cluster-available --cluster-identifier mywarehouse
```

No waiters exist for: `memorydb`, `docdb-elastic`, `keyspaces`, `dax`, `redshift-serverless`,
`timestream-influxdb`, `elasticache` serverless caches, and Redshift Data API statements.
Poll with a bounded loop, never an open-ended one:

```bash
# Bounded poll pattern: max 30 attempts, 20s apart (10 min cap)
for i in $(seq 1 30); do
  status=$(aws memorydb describe-clusters --cluster-name mymemdb \
    --query 'Clusters[0].Status' --output text)
  [ "$status" = "available" ] && break
  sleep 20
done

# Redshift Data API statement: poll describe-statement until FINISHED/FAILED, cap attempts
for i in $(seq 1 60); do
  s=$(aws redshift-data describe-statement --id "$SID" --query Status --output text)
  case "$s" in FINISHED|FAILED|ABORTED) break;; esac
  sleep 5
done
```

Expect long tails: Aurora cluster restores and Redshift classic resizes can exceed the
default waiter budget. Re-invoke the waiter once rather than looping it indefinitely, and
report a timeout instead of assuming failure.

## Verification after change

Prove the mutation landed with a targeted read-back, checking the exact field you changed:

```bash
# RDS: status plus whether anything is still pending
aws rds describe-db-instances --db-instance-identifier mydb \
  --query 'DBInstances[0].{Status:DBInstanceStatus,Pending:PendingModifiedValues,Class:DBInstanceClass}'

# RDS deletion: confirm the final snapshot exists before considering the delete complete
aws rds describe-db-snapshots --db-snapshot-identifier final-mydb-YYYYMMDD \
  --query 'DBSnapshots[0].Status'

# DynamoDB: table status, billing, and protection flags
aws dynamodb describe-table --table-name orders \
  --query 'Table.{Status:TableStatus,Billing:BillingModeSummary.BillingMode,DelProt:DeletionProtectionEnabled}'
aws dynamodb describe-continuous-backups --table-name orders

# Snapshot sharing: verify the attribute list matches intent (no stray "all")
aws rds describe-db-snapshot-attributes --db-snapshot-identifier mysnap \
  --query 'DBSnapshotAttributesResult.DBSnapshotAttributes'

# Resource policies: read back after put/delete
aws dynamodb get-resource-policy --resource-arn <table-arn>
aws redshift get-resource-policy --resource-arn <cluster-arn>

# ElastiCache: cluster and node status after modify or reboot
aws elasticache describe-replication-groups --replication-group-id mygroup \
  --query 'ReplicationGroups[0].{Status:Status,AutoFailover:AutomaticFailover}'

# Redshift: confirm pause/resume/resize took effect
aws redshift describe-clusters --cluster-identifier mywarehouse \
  --query 'Clusters[0].{Status:ClusterStatus,Public:PubliclyAccessible}'

# Data-plane writes: read the row you wrote
aws dynamodb get-item --table-name orders --key '{"pk":{"S":"tenant#42"},"sk":{"S":"order#1"}}' \
  --consistent-read
```

After any exposure-related change (snapshot attributes, resource policies, datashare
authorizations, public accessibility), the read-back is mandatory, not optional: verify the
grantee list contains exactly the intended principals and nothing else.
