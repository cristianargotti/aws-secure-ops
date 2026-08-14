# Incidents and break-glass: the documented exception path

Under incident pressure the protocol bends without breaking. The ladder gets
shorter, never absent; the stamps get louder, never dropped. Speed in an
incident comes from preparation and clear attribution, not from skipping the
steps that keep the audit trail honest. A responder who has rehearsed this
path moves faster than one improvising with an admin role, and leaves a trail
that reads as a response instead of an attack.

The reason is simple: an incident session is the session most likely to be
read later, line by line, by people who were not there. Incident-time events
look exactly like attacker events to automated analysis, privileged role,
unusual hour, rapid mutations, unless the trail itself says otherwise. The
incident stamp is how it says otherwise.

## The incident stamp

Ordinary work stamps as `<prefix>-<task-slug>`. Incident work stamps with a
distinct, recognizable shape:

```
AWS_SDK_UA_APP_ID="<prefix>-inc-<ticket>" aws ...
# e.g. xx-inc-4711
```

Rules, unchanged from the base protocol except for the shape:

- `<prefix>` is the operator's initials from the local policy file; the stamp
  names the accountable human, never a tool.
- `<ticket>` is the incident's tracking identifier. If the incident system is
  down or no ticket exists yet, use the date and a short slug
  (`xx-inc-0814-db-outage`) and open the ticket as soon as one can exist; the
  reconciliation step (below) links them.
- The stamp goes inline on every command of the incident, reads included.
  During reconciliation, this one string is the filter that separates incident
  actions from everything else in the trail. That is the payoff: one grep over
  CloudTrail reconstructs the whole response.
- Do not reuse the incident stamp for follow-up work after the incident is
  closed. Post-incident hardening is ordinary work with an ordinary stamp.

## Entering break-glass

Break-glass means assuming privilege you would not normally carry, or acting
in an account or on a resource you would not normally touch, because a live
incident requires it. It is an exception path, so the exception itself must be
captured at the moment it is taken, not reconstructed later:

1. **Authorization is explicit and named.** Before assuming the elevated role,
   record who authorized the escalation (a human with the standing to do so:
   the incident commander, the on-call lead, the service owner) and the one-
   sentence reason. If you are self-authorizing because nobody with standing is
   reachable, say exactly that, in writing, before acting; self-authorization
   is legitimate in a genuine emergency and indefensible when discovered
   retroactively with no record.
2. **The identity gate still runs.** `sts get-caller-identity` with the
   incident stamp, first call, every time. Confirm the account and role
   against the intent. Wrong-account mutations made "quickly, during the
   incident" are a classic way one incident becomes two.
3. **State the objective.** One sentence: what the incident is, what this
   session will attempt, what "contained" looks like. Everything the session
   does should trace back to that sentence.

Where the environment permits it, prefer a purpose-built break-glass role with
a pre-scoped policy and short session duration over a general administrator
role. That preparation is done in calm times; it is the single biggest speed
and safety gain available.

## Heightened logging, not reduced

Incident sessions log more, not less. Keep a running plain-text worklog as you
go, timestamps, commands, observations, decisions and who made them, even in
shorthand. Two minutes of note-taking during the incident saves two days of
CloudTrail archaeology after it. The worklog is also where the authorization
record from the previous section lives.

Announce the response in the incident channel or ticket as you act: "assuming
`<role>` in `<account>` under `<stamp>` to isolate the affected instance."
Parallel responders discovering each other through CloudTrail is its own
incident.

## What break-glass does not permit

Break-glass widens who may act and how fast. It does not widen what is
permissible. These hold at full strength during any incident:

- **Telemetry stays on.** Never disable or degrade trails, recorders,
  detectors, or loggers, not to "reduce noise", not to "speed things up".
  Disabling telemetry mid-incident is the signature move of an attacker
  covering tracks, and the trail cannot tell your intent from theirs.
- **One destructive target per command.** Containment often means isolating
  or terminating things quickly; it still happens one explained command at a
  time. A loop over a destructive verb during an incident is how a bad hour
  becomes a bad quarter. Prefer reversible containment (detach, quarantine
  security group, deny policy, snapshot-then-stop) over destruction wherever
  the incident allows; evidence preservation usually demands it anyway.
- **Frozen accounts stay frozen.** An incident in a live account is never a
  reason to mutate a frozen one. If the incident genuinely requires unfreezing
  an account, that is an organizational decision made by the people who froze
  it, recorded before the first mutation.
- **Secrets hygiene holds.** Rotating a compromised credential is common
  incident work; the new secret still never lands in a transcript, a chat, or
  remote-command text.
- **Exposure boundaries stay closed.** Opening a resource policy "temporarily,
  to restore service" is a one-command breach layered on top of an incident.
  If a boundary change is truly the fix, it gets the same explicit named
  authorization as the break-glass itself, and its own reconciliation entry.

The shortened ladder, concretely: feasibility reads compress to the minimum
that confirms the target (a describe and a glance at tags is still faster than
acting on the wrong resource), rehearsal may be skipped when the delay itself
is the damage, and confirmation is the incident commander's go rather than a
calm review. Nothing else comes off.

## Mandatory post-incident reconciliation

Break-glass is not closed when the incident is; it is closed when the
exception has been reconciled. Within a day of stand-down, while memory is
fresh:

1. **Pull the trail.** Query CloudTrail for the incident window and filter on
   the incident stamp (`userAgent` contains `app/<prefix>-inc-<ticket>`), plus
   a pass over the elevated role's events in the same window to catch anything
   that missed the stamp. This is a pointed, bounded read like any other.
2. **Reconcile against the worklog.** Every event either matches a worklog
   entry or becomes a question to answer now. Every worklog entry either
   appears in the trail or explains why not (a command that failed
   client-side, a read below the trail's management-event scope). Unexplained
   events are findings, however awkward.
3. **Restore least privilege.** Drop the break-glass role, revoke or expire
   any temporary credentials and sessions, remove temporary grants, policies,
   and security-group rules added during the response, and verify with reads
   that the removals took. Temporary access that outlives its incident is
   standing risk with an expired justification.
4. **Sweep the residue.** Incident-time resources, snapshots taken for
   evidence, quarantine security groups, temporary instances, are either
   promoted to properly tagged permanent resources with an owner, or deleted
   through the normal delete lane. Nothing stays in the ambiguous middle.
5. **Write the timeline.** A short document: when the incident started and
   ended, who authorized the break-glass and why, what was done (referencing
   the stamp so the trail is one query away), what was restored, what remains
   open. This is the artifact that turns an exception into a documented
   exception, and it is where the next incident's preparation begins.

A break-glass entry with no reconciliation record is indistinguishable, later,
from an unauthorized escalation. The reconciliation is what makes the whole
path defensible, and it is why the exception can exist at all.
