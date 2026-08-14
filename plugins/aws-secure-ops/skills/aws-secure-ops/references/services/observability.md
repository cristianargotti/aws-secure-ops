# Observability: secure operation patterns

Scope: monitoring, logging, tracing, audit, and cost-visibility services. Most traffic in this
domain is read-only, but the domain also contains the account's audit boundary (CloudTrail),
cross-account telemetry sharing (OAM, Logs destinations), and spend-committing operations
(budget actions, account plan upgrades). Treat those three areas with the same care as
infrastructure mutation.

## Services covered

- `cloudwatch`: metrics, alarms, dashboards, metric streams, anomaly detectors.
- `logs`: CloudWatch Logs log groups, Insights queries, subscription filters, cross-account delivery, data protection policies.
- `cloudtrail`: audit trails, CloudTrail Lake event data stores, resource policies, organization delegated admin.
- `xray`: traces, sampling rules, trace groups, encryption config, resource policies.
- `synthetics`: canaries and canary groups (scheduled browser and API probes).
- `rum`: real user monitoring app monitors, metric destinations, resource policies.
- `oam`: CloudWatch cross-account observability (sinks, links, sink policies).
- `application-insights`, `application-signals`: application-level monitoring, SLOs, log patterns.
- `evidently`: feature flags, launches, experiments (serves live traffic decisions).
- `ce`, `budgets`, `cur`, `bcm-data-exports`, `bcm-pricing-calculator`, `invoicing`, `freetier`: cost visibility, budget enforcement, billing exports.
- `compute-optimizer`, `cost-optimization-hub`, `trustedadvisor`, `support`, `health`: recommendations, checks, support cases, health events.
- `service-quotas`: quota values and increase requests.
- `resource-explorer-2`, `resource-groups`, `resourcegroupstaggingapi`: resource search, grouping, and tag inventory.
- Long tail: `applicationcostprofiler`, `bcm-recommended-actions`, `cloudtrail-data`, `pricing`.

## Querying safely

Always bound reads: use server-side time windows, name prefixes, `--max-items`, and `--query`.
Log and metric stores are effectively unbounded; a naive dump can stream gigabytes.

CloudWatch metrics and alarms:

```bash
aws cloudwatch describe-alarms --alarm-name-prefix "prod-" --state-value ALARM \
  --max-items 50 --query 'MetricAlarms[].{Name:AlarmName,State:StateValue,Updated:StateUpdatedTimestamp}'

aws cloudwatch get-metric-statistics --namespace AWS/EC2 --metric-name CPUUtilization \
  --dimensions Name=InstanceId,Value=i-0123456789abcdef0 \
  --start-time 2026-08-14T00:00:00Z --end-time 2026-08-14T06:00:00Z \
  --period 300 --statistics Average
```

CloudWatch Logs: never `get-log-events` without a time range, and prefer Insights queries
with an explicit `limit` clause. `start-query` is asynchronous: poll `get-query-results`
a bounded number of times.

```bash
aws logs describe-log-groups --log-group-name-prefix "/aws/lambda/orders" --max-items 25 \
  --query 'logGroups[].{Name:logGroupName,Retention:retentionInDays,Bytes:storedBytes}'

aws logs filter-log-events --log-group-name /aws/lambda/orders \
  --start-time 1755129600000 --end-time 1755133200000 \
  --filter-pattern "ERROR" --max-items 100

QID=$(aws logs start-query --log-group-name /aws/lambda/orders \
  --start-time 1755129600 --end-time 1755133200 \
  --query-string 'fields @timestamp,@message | filter @message like /ERROR/ | limit 50' \
  --query queryId --output text)
aws logs get-query-results --query-id "$QID"   # repeat max ~10 times, 3s apart
```

CloudTrail: `lookup-events` is rate-limited (2 TPS); always pass a time window and cap items.

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging \
  --start-time 2026-08-13T00:00:00Z --end-time 2026-08-14T00:00:00Z --max-items 50

aws cloudtrail get-trail-status --name main-trail \
  --query '{Logging:IsLogging,LastDelivery:LatestDeliveryTime,LastError:LatestDeliveryError}'
```

X-Ray, Synthetics, cost services:

```bash
aws xray get-trace-summaries --start-time 2026-08-14T00:00:00Z --end-time 2026-08-14T01:00:00Z \
  --filter-expression 'error = true' --query 'TraceSummaries[:20].[Id,ResponseTime]'

aws synthetics describe-canaries-last-run --max-results 20 \
  --query 'CanariesLastRun[].{Name:CanaryName,State:LastRun.Status.State}'

aws ce get-cost-and-usage --time-period Start=2026-08-01,End=2026-08-14 \
  --granularity DAILY --metrics UnblendedCost \
  --group-by Type=DIMENSION,Key=SERVICE --query 'ResultsByTime[-3:]'
```

Note: `ce` calls are billed per request (about 0.01 USD each); batch questions into few
grouped queries instead of looping per service or per day.

## Mutating safely

No service in this domain offers a `--dry-run` flag or a changeset-style staged flow.
Compensate with this discipline:

1. Read the current state first and save it (the read-back command doubles as your rollback source).
2. Mutate one named resource per command; avoid wildcard or multi-target forms
   (`delete-alarms` and `delete-dashboards` accept lists: pass exactly one name).
3. Read back immediately (see Verification section).

Tag at creation time where supported:

```bash
aws logs create-log-group --log-group-name /app/payments \
  --tags team=payments,env=prod
aws logs put-retention-policy --log-group-name /app/payments --retention-in-days 90

aws cloudwatch put-metric-alarm --alarm-name prod-payments-5xx \
  --namespace AWS/ApplicationELB --metric-name HTTPCode_Target_5XX_Count \
  --statistic Sum --period 300 --threshold 10 --comparison-operator GreaterThanThreshold \
  --evaluation-periods 2 --tags Key=team,Value=payments

aws synthetics create-canary --name checkout-probe ... --tags team=payments
```

`put-*` operations in this domain are upserts: `put-metric-alarm`, `put-dashboard`,
`put-retention-policy`, `put-event-selectors` silently overwrite the existing definition.
Fetch and archive the current definition before every put:

```bash
aws cloudwatch get-dashboard --dashboard-name ops-main --query DashboardBody --output text > dashboard.bak.json
aws cloudtrail get-event-selectors --trail-name main-trail > selectors.bak.json
```

Policy documents (`put-resource-policy` on logs, cloudtrail, xray, rum; `put-sink-policy` on oam;
`put-destination-policy` and `put-delivery-destination-policy` on logs) define trust boundaries.
Before applying one: enumerate every principal in the document, confirm no wildcard principals,
confirm any cross-account IDs are expected, and archive the previous policy.

Budget actions deserve special care at creation: a budget action can attach deny IAM policies
or stop EC2 and RDS instances when a threshold trips. Create them with
`--approval-model MANUAL` unless automatic enforcement was explicitly decided.

## Destructive traps

| Command                                                            | Why dangerous                                                                                                                | Safe procedure                                                                                                       |
| ------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `cloudtrail stop-logging`                                          | Silences the account audit trail; classic attacker move, breaks compliance                                                   | Require explicit approval; record the reason; `start-logging` plus `get-trail-status` immediately after the window   |
| `cloudtrail delete-trail` / `delete-event-data-store`              | Permanently ends audit collection; event data store deletion destroys retained audit history after its waiting period        | Confirm an org-level or replacement trail covers the account first; prefer `stop-logging` for temporary needs        |
| `cloudtrail put-event-selectors`                                   | Overwrites selectors; a narrow selector silently stops logging management or data events                                     | Archive current selectors, diff the new document, read back after apply                                              |
| `logs delete-log-group`                                            | Irreversibly deletes all log data in the group, all streams included                                                         | Verify retention needs and export (`create-export-task`) first; check `put-log-group-deletion-protection` status     |
| `logs put-retention-policy` with a short value                     | Not a delete command, but expires existing data once the new retention passes                                                | Confirm the current `storedBytes` and compliance retention before shortening                                         |
| `logs put-account-policy` / `put-destination-policy`               | Account-wide subscription policies can route every log group to one destination, including cross-account (exfiltration path) | Review destination ARN and principals; apply to a log-group subset via selection criteria first                      |
| `cloudwatch delete-alarms`                                         | Accepts up to 100 names; deleting alarms silences paging and can strand autoscaling policies that reference them             | One alarm per command; check `describe-alarms` `AlarmActions` for scaling or EC2 actions before deleting             |
| `cloudwatch set-alarm-state`                                       | Fires the alarm's configured actions: SNS pages, autoscaling, even EC2 stop or terminate actions                             | Inspect `AlarmActions` first; only use on alarms whose actions are safe to trigger, or after `disable-alarm-actions` |
| `budgets execute-budget-action`                                    | Immediately applies the action: deny policies attached, instances stopped                                                    | List the action definition (`describe-budget-action`) and its targets; get human confirmation                        |
| `oam delete-sink` / `delete-link`                                  | Severs cross-account telemetry flow for every linked source account; monitoring goes dark quietly                            | Enumerate `list-attached-links` on the sink first; coordinate with source account owners                             |
| `synthetics delete-canary`                                         | Deleting does not delete the canary's Lambda, layers, or S3 artifacts, and stops availability monitoring                     | `stop-canary` first, confirm coverage elsewhere, then delete and clean up the leftover Lambda and S3 objects         |
| `evidently stop-launch` / `stop-experiment` with `--desired-state` | Affects live traffic allocation; stopping a launch can snap all users back to the default variation                          | Confirm the served default is safe; prefer completing the launch schedule                                            |
| `xray put-encryption-config`                                       | Changes encryption for all trace data account-wide                                                                           | Record current config (`get-encryption-config`) before changing                                                      |

## Waiters and timing

Only CloudWatch ships waiters in this domain:

| Waiter                                   | Poll              | Cadence          | Max wait |
| ---------------------------------------- | ----------------- | ---------------- | -------- |
| `cloudwatch wait alarm-exists`           | `describe-alarms` | 5s x 40 attempts | 200s     |
| `cloudwatch wait composite-alarm-exists` | `describe-alarms` | 5s x 40 attempts | 200s     |

Everything else requires bounded manual polling. Poll with an explicit attempt cap and give up
loudly rather than looping forever:

- Logs Insights: poll `logs get-query-results --query-id` until `status` is `Complete`,
  every 3s, max 10 attempts; then `stop-query` if still running.
- Logs export: poll `logs describe-export-tasks --task-id` until `COMPLETED`, every 15s, max 40.
- CloudTrail Lake: poll `cloudtrail describe-query --query-id` until `FINISHED`, every 5s, max 24.
- CloudTrail import: poll `cloudtrail get-import --import-id`, every 30s, bounded by job size.
- Synthetics: after `start-canary`, poll `get-canary --query 'Canary.Status.State'` until
  `RUNNING`, every 10s, max 18; canary code changes take one schedule cycle to show results.
- Compute Optimizer exports: poll `describe-recommendation-export-jobs --job-ids`, every 30s, max 20.
- CE background jobs (`start-savings-plans-purchase-recommendation-generation`,
  `start-cost-allocation-tag-backfill`): results appear minutes to hours later; check status
  via the corresponding list call on a coarse cadence, do not tight-loop billed CE calls.

Alarm state itself is eventually consistent: after `put-metric-alarm` the state is
`INSUFFICIENT_DATA` until enough periods elapse; do not treat that as failure.

## Verification after change

Read back every mutation with a targeted describe or get, never by assuming success:

```bash
# Alarm created or updated
aws cloudwatch describe-alarms --alarm-names prod-payments-5xx \
  --query 'MetricAlarms[0].{State:StateValue,Actions:AlarmActions,Threshold:Threshold}'

# Retention or protection change on a log group
aws logs describe-log-groups --log-group-name-prefix /app/payments \
  --query 'logGroups[0].{Retention:retentionInDays,Protected:deletionProtectionEnabled}'

# Subscription filter landed
aws logs describe-subscription-filters --log-group-name /app/payments \
  --query 'subscriptionFilters[].{Name:filterName,Dest:destinationArn}'

# Trail is logging again after any CloudTrail change
aws cloudtrail get-trail-status --name main-trail --query IsLogging
aws cloudtrail get-event-selectors --trail-name main-trail

# Policy documents: diff against the archived copy
aws logs describe-resource-policies --query 'resourcePolicies[].policyName'
aws oam get-sink-policy --sink-identifier <sink-arn> --query Policy

# Cross-account link is flowing
aws oam list-links --query 'Items[].{Label:Label,Sink:SinkArn}'

# Canary running after start
aws synthetics get-canary --name checkout-probe --query 'Canary.Status.State'

# Budget and action state
aws budgets describe-budget-action --account-id <id> --budget-name <name> --action-id <id> \
  --query 'Action.{Status:Status,Approval:ApprovalModel}'
```

For deletions, verify absence: rerun the corresponding list or describe and expect an empty
result or `ResourceNotFoundException`. For CloudTrail specifically, close the loop through the
audit trail itself: a later `lookup-events` for the mutating event name proves both that the
change happened and that logging survived it.
