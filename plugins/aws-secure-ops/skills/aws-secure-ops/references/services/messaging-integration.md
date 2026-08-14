# Messaging and integration: secure operation patterns

Scope: queues, topics, streams, event buses, schedulers, state machines, email and SMS
delivery, and contact-center services. Most damage in this domain is silent: a deleted
message, a disabled rule, or a swapped receipt rule set produces no error, only missing
traffic discovered later.

## Services covered

- sqs: queues, dead-letter queues, message move tasks.
- sns: topics, subscriptions, platform endpoints, SMS.
- events (EventBridge): buses, rules, targets, archives, connections, api destinations.
- pipes: point-to-point source-to-target event pipes.
- scheduler (EventBridge Scheduler): cron and rate schedules with arbitrary targets.
- stepfunctions: state machines, executions, activities.
- kinesis: data streams, shards, consumers, resource policies.
- firehose: delivery streams to storage and analytics destinations.
- kinesisanalyticsv2: managed Flink applications (v1 legacy exists, same hazards).
- kafka (MSK) and kafkaconnect: clusters, configurations, connectors, SCRAM secrets.
- mq: ActiveMQ and RabbitMQ brokers, broker users.
- ses and sesv2: sending identities, configuration sets, receipt rules, suppression.
- pinpoint, pinpoint-sms-voice-v2: campaigns, journeys, phone numbers, spend limits.
- connect and satellites (connectparticipant, connectcampaigns, connectcampaignsv2,
  connectcases, qconnect, wisdom): contact-center instances, flows, live contacts.
- Long tail: swf, kinesisvideo and the kinesis-video-* data planes, chime and the
  chime-sdk-* family, mailmanager, appfabric, appintegrations, notifications,
  notificationscontacts, socialmessaging.

## Querying safely

Prefer targeted describes over full listings; several listings here enumerate customer
data (subscriptions, endpoints, contacts), not just infrastructure.

```bash
# SQS: attributes of one queue, named attributes only
aws sqs get-queue-attributes --queue-url "$Q" \
  --attribute-names ApproximateNumberOfMessages RedrivePolicy QueueArn
aws sqs list-queues --queue-name-prefix myapp --max-results 20

# SNS: one topic, then its subscriptions, bounded
aws sns get-topic-attributes --topic-arn "$T" \
  --query "Attributes.{Policy:Policy,Subs:SubscriptionsConfirmed}"
aws sns list-subscriptions-by-topic --topic-arn "$T" --max-items 50

# EventBridge: filter rules server-side by prefix, then inspect targets of one rule
aws events list-rules --name-prefix orders- --limit 25
aws events list-targets-by-rule --rule orders-fanout --query "Targets[].{Id:Id,Arn:Arn}"

# Step Functions: recent failures only, never the full history dump
aws stepfunctions list-executions --state-machine-arn "$SM" \
  --status-filter FAILED --max-items 20
aws stepfunctions get-execution-history --execution-arn "$EXE" \
  --reverse-order --max-items 30

# Kinesis: summary first (cheap), shard detail only when needed
aws kinesis describe-stream-summary --stream-name app-events
aws kinesis list-shards --stream-name app-events --max-results 100

# MSK / MQ: one cluster or broker by ARN or id
aws kafka describe-cluster-v2 --cluster-arn "$ARN" \
  --query "ClusterInfo.{State:State,Type:ClusterType}"
aws mq describe-broker --broker-id "$BID" \
  --query "{State:BrokerState,Engine:EngineType,Ver:EngineVersion}"

# SES v2: one identity, account posture
aws sesv2 get-email-identity --email-identity example.com \
  --query "{Verified:VerifiedForSendingStatus,Dkim:DkimAttributes.Status}"
aws sesv2 get-account --query "{Enabled:SendingEnabled,Quota:SendQuota}"

# Connect: scope every call to one instance id; listings page hard
aws connect list-queues --instance-id "$IID" --max-items 50
aws connect describe-contact --instance-id "$IID" --contact-id "$CID"
```

Reads that are not neutral in this domain:

- `sqs receive-message` is not a read: it hides messages for the visibility timeout,
  increments receive counts, and can push messages toward a dead-letter queue. Peek
  only on queues without active consumers, or accept the side effect knowingly.
- `stepfunctions get-activity-task` and `swf poll-for-*` consume work units that real
  workers are waiting for. Do not poll production activities to "look".
- `kinesis-video-signaling get-ice-server-config` returns TURN usernames and passwords;
  `kinesis-video-archived-media get-hls|dash-streaming-session-url` and
  `kinesisanalyticsv2 create-application-presigned-url` return URLs that grant access
  to anyone holding them. Treat outputs as secrets, never paste into logs or tickets.
- `connect get-federation-token` and `connectparticipant get-authentication-url` emit
  live session credentials.

## Mutating safely

No service in this domain supports `--dry-run`. Compensate with staged flows: render
the change as JSON first, review it, then apply to exactly one named resource.

- One target per command. Avoid `--cli-input-json` files that batch many resources,
  and avoid batch variants (`delete-message-batch`, `batch-put-contact`,
  `put-outbound-request-batch`) unless the batch itself was reviewed line by line.
- Tag at creation time, in the create call itself:

```bash
aws sqs create-queue --queue-name myapp-orders \
  --tags Purpose=order-intake,Owner=platform,Env=prod
aws sns create-topic --name myapp-alerts \
  --tags Key=Purpose,Value=alerting Key=Env,Value=prod
aws events put-rule --name orders-nightly --schedule-expression "cron(0 6 * * ? *)" \
  --state DISABLED --tags Key=Purpose,Value=batch-kickoff
aws stepfunctions create-state-machine --name order-flow --role-arn "$ROLE" \
  --definition file://flow.asl.json --tags key=Purpose,value=orders
```

Note the three different tag syntaxes above; verify per service with
`aws SERVICE OPERATION help` before running.

- Create disabled, then enable. EventBridge rules (`--state DISABLED`), schedules
  (`--state DISABLED`), and pipes (create then `start-pipe`) all support starting
  cold. Wire targets and permissions while nothing fires, enable last.
- Validate offline where possible: `aws stepfunctions validate-state-machine-definition`
  and `aws events test-event-pattern` check syntax without touching live traffic.
  `aws stepfunctions test-state` exercises a single state in isolation.
- Policy edits (queue policy, topic policy, event bus permission, cluster policy,
  SES identity policy) are trust-boundary changes: fetch the current policy, diff the
  proposed document locally, and apply the full merged document. `set-queue-attributes`
  and `set-topic-attributes` replace the named attribute wholesale; there is no
  server-side merge.
- Subscription and target changes redirect data flows. Adding an SNS subscription,
  an EventBridge target, or a Firehose destination points production traffic at a new
  principal; confirm the destination account and resource before applying.
- Sends are spend and reputation events. `ses send-email`, `sns publish`,
  `pinpoint-sms-voice-v2 send-text-message`, and campaign start operations reach real
  recipients; test against sandbox identities, verified destination numbers, or a
  personal endpoint first. Never raise `set-*-spend-limit-override` casually.

## Destructive traps

| Command                                                                                    | Why dangerous                                                                                    | Safe procedure                                                                                               |
| ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------ |
| `sqs purge-queue`                                                                          | Deletes every message, irreversible, still deleting for up to 60s                                | Prefer draining via `start-message-move-task` to a holding queue; purge only with explicit confirmation      |
| `sqs delete-queue`                                                                         | Queue and all messages gone; consumers fail; name reusable after 60s                             | Snapshot attributes and redrive policy first; confirm zero producers via metrics                             |
| `sns delete-topic` / `unsubscribe`                                                         | Publishers silently lose fanout; deleted subscriptions do not auto-restore                       | Export subscriptions (`list-subscriptions-by-topic`) before deletion                                         |
| `events disable-rule` / `remove-targets`                                                   | Downstream automation stops firing with no error anywhere                                        | Record rule state and targets first; disable one rule, watch consumer metrics, keep the enable command ready |
| `ses set-active-receipt-rule-set`                                                          | Swaps inbound mail processing for the whole account; calling with no rule set disables receiving | Describe the active set first (`describe-active-receipt-rule-set`), change during a low-traffic window       |
| `ses update-account-sending-enabled --no-enabled` / `sesv2 put-account-sending-attributes` | Halts all outbound mail account-wide                                                             | Prefer per-configuration-set sending toggles; account-level only under incident response                     |
| `sesv2 delete-suppressed-destination`                                                      | Re-enables sending to an address that bounced or complained; reputation and compliance risk      | Verify the suppression reason first with `get-suppressed-destination`                                        |
| `kinesis decrease-stream-retention-period`                                                 | Records older than the new retention become unreadable immediately                               | Confirm consumers have checkpointed past the horizon; lower in steps                                         |
| `kinesis merge-shards` / `split-shard` / `update-shard-count`                              | Resharding churns consumer leases and doubles billed shard hours during transition               | One operation at a time, wait for ACTIVE between steps                                                       |
| `kinesis stop-stream-encryption`, `firehose stop-delivery-stream-encryption`               | Disables encryption at rest while traffic continues                                              | Treat as a security change: document, get approval, verify with describe afterwards                          |
| `kafka reboot-broker`, `mq reboot-broker`                                                  | Rolling client disconnects; unacked messages redelivered                                         | One broker at a time, confirm cluster/broker healthy before the next                                         |
| `mq promote`                                                                               | Failover: replica becomes primary, old primary demoted, clients reconnect                        | Confirm replication is caught up and a maintenance window exists                                             |
| `stepfunctions stop-execution`, `swf terminate-workflow-execution`                         | Kills an in-flight business process midway; partial side effects remain                          | Read `get-execution-history` first, prefer waiting for a safe state; record the execution ARN stopped        |
| `scheduler delete-schedule`, `delete-schedule-group`                                       | Group deletion removes every schedule inside it                                                  | Delete single schedules by name; never delete a group to remove one schedule                                 |
| `connect stop-contact`                                                                     | Drops a live customer call or chat                                                               | Confirm contact id against `describe-contact`; prefer `transfer-contact`                                     |
| `connect release-phone-number`, `pinpoint-sms-voice-v2 release-phone-number`               | Number leaves the account and may not be reclaimable; inbound routes die                         | Verify no flow or pool references the number; port or re-map first                                           |
| `connectcampaigns[v2] stop-campaign`                                                       | Halts live outbound dialing mid-campaign                                                         | Prefer `pause-campaign` (resumable); stop only to end the campaign                                           |
| `chime redact-*-message`, `chime-sdk-messaging redact-channel-message`                     | Message content is removed permanently                                                           | Confirm the exact message id; export content first if retention requires it                                  |
| `firehose delete-delivery-stream`                                                          | In-flight records can be lost (`--allow-force-delete` skips draining)                            | Stop producers, let buffers flush, then delete without force                                                 |

## Waiters and timing

Only three waiters exist in this domain:

| Service | Waiter            | Delay x attempts | Max wait |
| ------- | ----------------- | ---------------- | -------- |
| kinesis | stream-exists     | 10s x 18         | 3m       |
| kinesis | stream-not-exists | 10s x 18         | 3m       |
| ses     | identity-exists   | 3s x 20          | 1m       |

```bash
aws kinesis wait stream-exists --stream-name app-events
aws ses wait identity-exists --identities example.com
```

Everything else needs bounded manual polling: poll a status field at a fixed interval
with a hard attempt cap, never an open-ended loop.

```bash
# Pattern: 12 attempts x 10s, then give up loudly
for i in $(seq 1 12); do
  S=$(aws pipes describe-pipe --name my-pipe --query CurrentState --output text)
  [ "$S" = "RUNNING" ] && break; sleep 10
done; echo "final state: $S"
```

What to poll, per service:

- sqs: nothing to wait for on create/delete (allow 60s before reusing a name);
  `get-queue-attributes` ApproximateNumberOfMessages for drain progress.
- events / scheduler: changes are fast; read back the rule or schedule state once.
- pipes: `describe-pipe` CurrentState (CREATING, RUNNING, STOPPED, FAILED).
- stepfunctions: `describe-execution` status; state machine deletion is async, poll
  `describe-state-machine` until it errors with not found.
- kinesisanalyticsv2: `describe-application` ApplicationStatus (STARTING, RUNNING,
  STOPPING); start and stop can take minutes.
- kafka: `describe-cluster-v2` State; cluster create and update-broker operations run
  15 to 60+ minutes, poll at 60s intervals with a generous cap, and track
  `list-cluster-operations-v2` for the active operation ARN.
- kafkaconnect: `describe-connector` connectorState.
- mq: `describe-broker` BrokerState (CREATION_IN_PROGRESS, RUNNING, REBOOT_IN_PROGRESS);
  creates take about 15 minutes, poll at 30 to 60s.
- ses / sesv2: DKIM and domain verification depend on DNS propagation; poll
  `get-email-identity` a few times, then stop and re-check later rather than spinning.
- firehose: `describe-delivery-stream` DeliveryStreamStatus.
- connect: `describe-instance` InstanceStatus after create or replicate.

## Verification after change

Read back the exact attribute you changed; do not trust the empty success response.

```bash
# Queue attribute or policy change landed
aws sqs get-queue-attributes --queue-url "$Q" --attribute-names Policy RedrivePolicy

# Topic policy and subscription set
aws sns get-topic-attributes --topic-arn "$T" --query "Attributes.Policy"
aws sns list-subscriptions-by-topic --topic-arn "$T" --max-items 50

# Rule state, targets, and the event bus policy
aws events describe-rule --name orders-fanout --query "{State:State,Bus:EventBusName}"
aws events list-targets-by-rule --rule orders-fanout
aws events describe-event-bus --name default --query Policy

# State machine definition version actually serving traffic
aws stepfunctions describe-state-machine --state-machine-arn "$SM" \
  --query "{Rev:revisionId,Updated:updateDate}"

# Stream: status, retention, encryption
aws kinesis describe-stream-summary --stream-name app-events --query \
  "StreamDescriptionSummary.{St:StreamStatus,Ret:RetentionPeriodHours,Enc:EncryptionType}"

# Broker or cluster settled after reboot/update
aws mq describe-broker --broker-id "$BID" --query BrokerState
aws kafka describe-cluster-v2 --cluster-arn "$ARN" --query ClusterInfo.State

# Mail posture after identity or sending changes
aws sesv2 get-email-identity --email-identity example.com
aws sesv2 get-account --query "{Sending:SendingEnabled}"
aws ses describe-active-receipt-rule-set --query "Metadata.Name"

# Message delivery proof: send a canary, then confirm consumption
aws sqs send-message --queue-url "$Q" --message-body "canary-$(date +%s)"
aws sqs get-queue-attributes --queue-url "$Q" \
  --attribute-names ApproximateNumberOfMessages

# Phone number and campaign state
aws pinpoint-sms-voice-v2 describe-phone-numbers --phone-number-ids "$PID"
aws connectcampaignsv2 get-campaign-state --id "$CAMPAIGN_ID"
```

After any policy or permission change, also verify from the consumer side: run the
narrowest possible read or send as the granted principal, confirm it succeeds, and
confirm a non-granted principal still fails.
