# The local decision ledger and CloudTrail reconciliation

## Why a local decision trail exists

CloudTrail is the organization's audit trail: authoritative, tamper-evident,
and shared. It records what the account saw. It does not record what your
tooling decided locally -- which commands the gate allowed through, which ones
it paused for confirmation, and which ones it refused before any API call was
made. Denied commands, by definition, never reach CloudTrail at all.

The local decision ledger fills that gap. The gate appends one line for every
aws invocation it inspects -- allow, ask, and deny alike -- so the operator
keeps a private, chronological record of their own decisions. It serves two
purposes:

1. **Self-accountability.** At the end of a work session you can answer, from
   your own records, "what did I run, under which profile class, with which
   purpose stamp, and what did the gate stop?" That answer exists even for
   calls that never produced an audit event.
2. **Fast reconciliation.** Every allowed call should also appear in
   CloudTrail carrying your purpose stamp in its userAgent. The ledger gives
   you the exact stamps and time windows to check, turning "did my work reach
   the trail?" into a two-minute pointed lookup instead of a fishing
   expedition.

The ledger is a convenience layer for the operator, not a compliance control.
CloudTrail remains the source of truth for what actually happened in the
account; the ledger is the source of truth for what the gate decided on this
machine.

## Where it lives

- Path: the value of `AWS_OPS_LEDGER_FILE` if set, otherwise
  `~/.claude/aws-ops-ledger.jsonl`.
- Format: JSON Lines -- one self-contained JSON object per line, appended in
  decision order.

## Line schema

Every line has exactly these keys, in this order:

```json
{
  "ts": "2026-05-18T12:05:44+00:00",
  "service": "s3api",
  "operation": "put-bucket-policy",
  "class": "modify",
  "sensitive": true,
  "decision": "ask",
  "stamp": "xx-bucket-hardening",
  "profile": "example-readonly",
  "profile_class": "readonly"
}
```

| Field           | Type          | Meaning                                                                            |
| --------------- | ------------- | ---------------------------------------------------------------------------------- |
| `ts`            | string        | Decision time, ISO-8601 with UTC offset                                            |
| `service`       | string        | CLI service token (`ec2`, `s3api`, ...)                                            |
| `operation`     | string        | CLI operation (`describe-instances`, ...)                                          |
| `class`         | string        | Classification: `read`, `execute`, `create`, `modify`, `destroy`                   |
| `sensitive`     | bool          | Whether the sensitive flag applied                                                 |
| `decision`      | string        | `allow`, `ask`, or `deny`                                                          |
| `stamp`         | string / null | Purpose stamp from `AWS_SDK_UA_APP_ID`, if one was set                             |
| `profile`       | string / null | Named profile on the command, if any                                               |
| `profile_class` | string / null | Policy class of that profile (`readonly`, `admin`, `frozen`, `personal`), if known |

## How decisions map to lines

One line is written per inspected invocation. When a command is denied, the
whole shell command is blocked and nothing in it runs, so every invocation in
that command is recorded with `decision` `deny`: the ledger never shows an
`allow` line for a call that never reached AWS. An `ask` line means the gate
paused the command for confirmation; whether the call then ran depends on the
operator's answer, which the gate does not observe. A few command-level
denials are decided before any invocation is classified (for example
`--no-verify-ssl`); these block the command without writing a per-invocation
line.

## Privacy guarantees

The ledger records **metadata only**. By contract it never contains:

- raw command text or full argument lists,
- argument values (resource names, ARNs, file paths, queries),
- tag values,
- credentials, tokens, or any other secret material.

Service, operation, class, decision, stamp, and profile name are the entire
payload. This is deliberate: the file lives unencrypted in the home directory,
and a record that cannot contain secrets cannot leak them. Tooling that reads
the ledger should honor the same boundary -- display the contract fields and
nothing else, and never "enrich" ledger output with recalled command text.

Ledger writing is also **best-effort by design**: a full disk, a bad path, or
a permission problem never blocks, delays, or changes a gate decision. The
gate proceeds silently. The practical consequence for the operator: an absent
ledger line is weak evidence, while CloudTrail remains strong evidence.

## Disabling the ledger

Two supported ways:

- Set `"ledger": false` in the local policy file. The gate stops writing
  entirely.
- Point `AWS_OPS_LEDGER_FILE` at a null sink (for example `/dev/null`) for a
  session-scoped mute without touching the policy.

Disabling the ledger changes nothing about gate decisions -- classification,
confirmation prompts, and denials behave identically. You only lose the local
record.

## Reading the ledger

`scripts/aws-ops-ledger.py` is a small, dependency-free CLI over the file:

```
python3 scripts/aws-ops-ledger.py tail 20     # last 20 decisions, one line each
python3 scripts/aws-ops-ledger.py summary     # counts by decision/class, span
python3 scripts/aws-ops-ledger.py stamps      # distinct purpose stamps + counts
python3 scripts/aws-ops-ledger.py reconcile   # print CloudTrail lookups to run
python3 scripts/aws-ops-ledger.py rotate      # start a fresh file (see below)
```

It is offline and never runs an aws command. Every subcommand except `rotate`
is read-only. A missing or empty ledger is reported clearly and exits zero.

## Rotation

The ledger grows one line per inspected invocation and is never trimmed on the
write path, so over a long-lived machine it can accumulate. `rotate` is the one
maintenance action the tool performs:

```
python3 scripts/aws-ops-ledger.py rotate
python3 scripts/aws-ops-ledger.py rotate --if-larger-than <bytes>
```

- `rotate` renames the active ledger aside to a timestamped sibling in the same
  directory (`<name>-YYYYMMDD-HHMMSS.<suffix>`, UTC). The next gate write
  recreates the active file from scratch, so a fresh file starts empty while
  the full history is preserved under its timestamped name.
- `--if-larger-than <bytes>` rotates only when the file strictly exceeds that
  size; at or under it the call is a no-op that exits zero. This is the form
  the session watchdog uses: it invokes rotation automatically once the active
  ledger grows past roughly 5 MB, so the file stays bounded without operator
  attention.

Rotation is best-effort and safe by construction. It only ever renames -- never
deletes, edits, or rewrites -- so no recorded line can be lost or corrupted, and
the metadata-only contract carries over to the rotated file unchanged. A missing
or empty ledger is a no-op that exits zero; any real failure exits nonzero with
a message on stderr and leaves the original file exactly where it was. The path
honored is the same one every other subcommand uses: `AWS_OPS_LEDGER_FILE` if
set, otherwise the default under the home directory.

Rotated siblings are ordinary JSONL files. Point `AWS_OPS_LEDGER_FILE` at one
to read it with `tail`, `summary`, `stamps`, or `reconcile`, and delete old
rotations yourself once you no longer need the local record.

## Reconciling stamps against CloudTrail

Every stamped call sets `AWS_SDK_UA_APP_ID`, which the AWS SDK embeds in the
request's user agent as `app/<stamp>`. CloudTrail records that userAgent on
each event, so a purpose stamp in the ledger should be findable in the trail.
Reconciliation closes the loop: local decision, remote evidence.

The workflow:

1. Run `stamps` to see which stamps you used and their time windows.
2. Run `reconcile` to get ready-to-paste `aws cloudtrail lookup-events`
   commands, one per recent stamp. They are printed, not executed -- you run
   them deliberately, under a read-only profile, with a stamp on the lookup
   itself.
3. Confirm each stamp's events appear in the trail with plausible event names
   and times.

Two mechanics worth understanding:

- **userAgent is not a lookup attribute.** `lookup-events` can filter
  server-side only on attributes like EventName, Username, or EventSource --
  not userAgent. The printed commands therefore pull a small, time-bounded
  page (`--max-items` kept low, `--start-time`/`--end-time` from the ledger
  window plus a small buffer) and filter client-side with `--query` on the
  raw event JSON, which contains the userAgent. This keeps the lookup pointed
  and bounded rather than paging the whole trail.
- **Visibility lag.** CloudTrail typically delivers events to Event history
  within about 5 to 15 minutes of the API call. A stamp that is missing
  immediately after the fact usually means "not delivered yet", not "not
  recorded". Wait out the lag and re-run the lookup before treating a gap as
  a finding.

If a stamp still cannot be found after the lag, widen the time window
slightly, then consider the honest explanations in order: the call was a
service or region whose events land in a different trail view, the call
failed client-side before reaching AWS, or the stamp was not actually set on
that command. Each of these is checkable from the ledger line itself.
