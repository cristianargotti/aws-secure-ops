# Waiters and timing: response times done right

AWS is asynchronous. Most mutations return the moment the control plane
accepts the request, long before the state exists. Correctness therefore
includes WAITING correctly: using the service's waiter when one exists,
polling with discipline when one does not, and respecting eventual
consistency. Tight retry loops are triply wrong: they hammer rate limits,
they fill the audit trail with noise that reads like malfunctioning
automation, and they still miss states that take minutes.

## Built-in waiters

```bash
aws ec2 wait volume-available --volume-ids vol-0abc
aws cloudformation wait stack-update-complete --stack-name <s>
aws rds wait db-instance-available --db-instance-identifier <id>
```

The complete waiter map of the installed CLI is
`references/inventory/waiters.csv` with columns
`service,waiter,delay_seconds,max_attempts,polled_operation`. The time budget
of a waiter is `delay x attempts`; know it before you start so a timeout is
information, not surprise. Representative budgets:

| Waiter                                 | Polls           | Budget |
| -------------------------------------- | --------------- | ------ |
| `ec2 volume-available`                 | every 15s x 40  | 10 min |
| `ec2 instance-running`                 | every 15s x 40  | 10 min |
| `cloudformation stack-update-complete` | every 30s x 120 | 60 min |
| `rds db-instance-available`            | every 30s x 60  | 30 min |
| `ecs services-stable`                  | every 15s x 40  | 10 min |

A waiter that exits non-zero after its budget is a signal to investigate the
resource's state and status reason, not to immediately re-run the waiter.

## Bounded polling when no waiter exists

```bash
# Pattern: generous sleep, hard attempt cap, explicit success condition
for i in 1 2 3 4 5 6 7 8; do
  state=$(aws <svc> describe-<thing> --ids <id> --query '...State' --output text)
  [ "$state" = "ACTIVE" ] && break
  sleep 20
done
```

- Sleep at least 10 to 15 seconds between polls for infrastructure state; a
  human-triggered check every few seconds is indistinguishable from a stuck
  script.
- Cap attempts. Decide up front what "took too long" means and what you will
  do then.
- Poll the READ operation, never re-issue the mutation "to be sure". Re-issued
  mutations without idempotency tokens double-create.
- Async job APIs (query engines, exports, batch jobs) publish a status
  operation (`get-query-results`, `describe-export-tasks`); poll that, and
  cancel jobs you abandon.

## Eventual consistency: where patience is required

| Surface                                          | Typical lag                             | Consequence                                                                                                        |
| ------------------------------------------------ | --------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| IAM changes (policies, roles, instance profiles) | seconds to ~1 min                       | The first "AccessDenied" right after a grant may be propagation, not misconfiguration; wait once before diagnosing |
| Newly created role usable by a service           | up to minutes                           | Attach-then-use flows need a deliberate pause or retry-once                                                        |
| CloudTrail event visibility                      | commonly up to ~15 min                  | "Not in lookup-events yet" is not "did not happen"                                                                 |
| CloudWatch metric datapoints                     | 1 to several min                        | Verification reads on fresh metrics need a window, not an instant                                                  |
| DNS (Route 53 + resolver caches)                 | record TTL                              | Verify with a direct resolver query, then respect TTL for the fleet                                                |
| CDN distribution config deploys                  | minutes                                 | The API says Deployed before every edge agrees                                                                     |
| S3                                               | strong read-after-write within a region | Cross-region replication still lags; verify in the destination                                                     |

## CLI timeouts, retries, exit codes

```bash
# Connection and read timeouts (seconds); defaults are 60/60
aws --cli-connect-timeout 10 --cli-read-timeout 30 <...>

# Client-side retry behavior: adaptive mode backs off under throttling
AWS_RETRY_MODE=adaptive AWS_MAX_ATTEMPTS=5 aws <...>
```

- Prefer `adaptive` retry mode for scripted sequences; it rate-limits itself
  under `ThrottlingException` instead of stampeding.
- `--no-cli-pager` for anything scripted; a surprise pager blocks pipelines.
- Exit codes: `0` success; `1` the service returned an error for the request;
  `2` the command line itself could not be parsed; `130` interrupted;
  `252-255` CLI configuration/argument/environment failures. Branch on them
  explicitly in scripts; "non-zero" alone conflates a typo with a denial.
- A `Throttling`/`Rate exceeded` error is a pacing instruction. Slow down,
  widen sleeps, batch reads by ID list; do not raise attempts and push.

## Time in the record

- Timestamps in the audit trail are UTC; correlate with local clocks
  explicitly when reconstructing timelines.
- Long-running operations deserve a stated expectation in the worklog ("stack
  update, expected under 10 minutes") so that overruns become visible facts
  instead of vague waiting.
