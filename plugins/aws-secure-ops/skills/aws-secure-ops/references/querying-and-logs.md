# Querying safely: pointed reads, bounded logs

Reads are "free" only operationally. Every read is still an audit event, still
counts against rate limits, still costs money in some services (log scans,
S3 Select, Athena), and an unbounded dump can still exfiltrate more data than
any single secret. The discipline: name what you want, filter it server side,
cap what comes back, and state why you are looking.

## Server-side vs client-side filtering

`--query` is JMESPath applied CLIENT-side: it trims the output, not the API
call. The server still returned everything. Prefer the service's own filter
parameters, then use `--query` only to shape what you print:

```bash
# Server-side: the API returns only matching volumes
aws ec2 describe-volumes --filters Name=tag:Name,Values=TEST-restore-check

# Client-side shaping of an already-bounded response
aws ec2 describe-volumes --volume-ids vol-0abc \
  --query 'Volumes[0].{state:State,size:Size,az:AvailabilityZone}'
```

Most describe/list calls accept a direct ID list; passing several IDs to ONE
call is the legitimate form of batching and beats N sequential calls both for
rate limits and for how the session reads:

```bash
aws ec2 describe-instances --instance-ids i-0a i-0b i-0c
```

## Pagination, always bounded

```bash
aws logs describe-log-groups --max-items 50
aws s3api list-objects-v2 --bucket <b> --prefix logs/2026/ --max-items 100
```

- `--max-items` caps total items (the CLI handles tokens); `--page-size` caps
  per-request size to be gentle on the API.
- Never dump an entire large table/bucket/trail "to look around". If a sweep
  is genuinely required (an audit), say so first, bound it, and prefer the
  service's own export/report features over brute enumeration.
- `--no-paginate` prevents the CLI from silently walking every page.

## CloudWatch Logs

```bash
# Bounded filter: time window + pattern + limit, never an open-ended dump
aws logs filter-log-events --log-group-name <g> \
  --start-time $(date -v-2H +%s000) --end-time $(date +%s000) \
  --filter-pattern '"ERROR"' --max-items 200

# Logs Insights for anything analytical: window + limit are part of the query
aws logs start-query --log-group-name <g> \
  --start-time <epoch> --end-time <epoch> \
  --query-string 'fields @timestamp, @message | filter @message like /ERROR/ | sort @timestamp desc | limit 100'
aws logs get-query-results --query-id <id>   # poll per waiters-and-timing.md

# Live tail is for active incidents only; give it --since and a filter
aws logs tail <group> --since 15m --filter-pattern '"ERROR"'
```

Insights queries bill per byte scanned: narrow the time window and the log
groups before widening the query. Stop finished Insights queries you no longer
need (`aws logs stop-query`).

## CloudTrail lookups

`lookup-events` is heavily rate limited (single-digit requests per second) and
returns 90 days of management events. Use it pointed, one attribute at a time:

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteVolume \
  --start-time 2026-01-15T00:00:00Z --max-items 5
```

Event delivery lags minutes behind real time (commonly up to ~15); "not there
yet" is not "did not happen". For anything analytical across many events, use
the trail's S3/Athena path, not lookup-events in a loop.

## Log and output hygiene

- Logs contain what applications leaked into them: PII, tokens, session IDs,
  internal hostnames. Never paste raw log dumps into shared documents, tickets,
  or chat; extract the relevant lines and redact identifiers.
- Keep working excerpts in a scratch location, not in repositories.
- Reads that return secret material (`get-secret-value`, parameter reads with
  decryption, credential generators) are not "just reads": pipe them into the
  consumer, never onto the screen. Existence and metadata checks
  (`list-secrets`, `describe-secret`) answer most questions without touching
  the value.

## Shaping a read session

- Prefix the block with one line of purpose, stamp every command
  (`AWS_SDK_UA_APP_ID`), and keep the block on one topic.
- Space out large read sequences; rapid-fire enumeration from a human identity
  is indistinguishable from credential-theft reconnaissance, and is exactly
  what automated trail analysis is tuned to flag.
- Use a read-only profile for read sessions; the role on the event does more
  for how the session reads than any comment can.
