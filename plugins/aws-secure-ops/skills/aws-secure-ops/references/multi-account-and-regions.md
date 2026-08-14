# Multi-account and multi-region hygiene

Most serious operational mistakes in AWS are not exotic. They are the right
command run as the wrong principal, in the wrong account, or in the wrong
region. All three failure modes share a root cause: trusting context that was
implied (a profile name, an exported variable, a default region) instead of
context that was verified. This reference is the discipline for crossing those
boundaries deliberately.

## Never trust a profile name

A profile is a local label over remote credentials, and nothing keeps the two
in sync. Profiles named `readonly` have been found carrying administrator
roles; profiles named after one account have been found pointing at another
after a config edit, an SSO refresh, or a copy-paste between machines. The
name is a hint; the only authority is the STS answer:

```
AWS_SDK_UA_APP_ID="<stamp>" aws sts get-caller-identity --profile <profile>
```

Read all three fields of the response, not just the exit code:

- **Account** matches the account you intend to operate in.
- **Arn** names the role you intend to carry, at the privilege tier the task
  needs and no more.
- **UserId** is the session; for assumed roles it ends in the session name,
  which should attribute the human operator (below).

Run the gate at the start of every task, and again after anything that could
have changed the answer: an assume-role, an SSO login, a new terminal, a
switch between accounts mid-task. Never operate on an implicit profile or on
inherited environment credentials; `--profile` goes on every command, so that
each command carries its own identity claim instead of borrowing whatever the
environment happens to hold.

## Assume-role discipline

Cross-account work is done by assuming a role in the target account, and every
choice in that call is audit-visible on every subsequent event.

**Session names attribute the human.** The `--role-session-name` lands in the
assumed role's ARN on every CloudTrail event the session produces. It names
the accountable operator, never a tool, an automation, or a generic label:

```
aws sts assume-role \
  --role-arn arn:aws:iam::111111111111:role/example-readonly \
  --role-session-name operator-name \
  --external-id <external-id-if-required>
```

A trail full of events from `role/example-admin/cli-session` answers no
questions; the same events from `role/example-admin/operator-name` answer the
first one before it is asked. If a shared convention exists in the local
policy file, follow it; otherwise the operator's corporate identity is the
session name.

**External ID where applicable.** When a role's trust policy requires an
external ID, typically roles granted to or by another organization, pass it,
and treat it like a credential: it lives in configuration, not in transcripts
or documents. Never remove or weaken an external-id condition to make an
assume-role succeed; the condition is the confused-deputy protection, and a
failure against it is a configuration finding, not friction.

**Assume the least role that works.** When the target account offers several
roles, the choice is the same least-privilege decision as profile selection:
read-only role for reads, the narrower operational role over the broad one for
mutations, admin only when the specific commands require it, and back down
afterwards. The role is stamped on every event; carrying admin "in case" turns
a routine session into one that invites review. Note that `sts assume-role`
mints credentials, the inventory classes it as sensitive for a reason, so each
assumption is itself a deliberate, stamped act, not a reflex.

**Other teams' accounts.** Access to an account another team owns, even
read-only, is a guest pass. Pointed reads only, one clear purpose per session,
and mutations only on the owner's explicit request, in writing, with the
request referenced in the purpose stamp or worklog.

## Regions: name it, verify it, every time

Operating in the wrong region is a top cause of real incidents and of
duplicate resources. The mechanics make it easy: the CLI resolves region from
a chain of defaults (flag, environment, profile config), and a profile whose
default region is not the one in your head produces commands that succeed,
quietly, somewhere else. The failure has two faces:

- **Phantom absence.** A describe in the wrong region returns empty, which
  reads as "the resource does not exist", which leads to re-creating it,
  which is how duplicate, untagged, unmonitored infrastructure is born, and
  billed.
- **Wrong-target mutation.** A modify or delete lands on the same-named
  resource in another region. Same-named resources across regions are common
  precisely because environments are stamped out symmetrically.

The discipline:

- **Explicit `--region` on every mutation**, no exceptions, and on any read
  whose answer feeds a decision. Typing the region is the act of deciding it;
  a default is the absence of a decision.
- **Verify region at the identity gate.** `get-caller-identity` is global and
  will not catch a region mistake, so extend the gate: state the intended
  region alongside account and role, and confirm the profile's default agrees
  (`aws configure get region --profile <profile>`) or accept that every
  command must carry the flag. Account, role, region: the gate has three
  answers, not two.
- **Empty result in hand? Check the region before concluding absence.** The
  cheapest habit in this file, and the one that prevents the duplicate-
  resource failure entirely.

**Global versus regional services.** IAM, STS (by default), Route 53,
CloudFront, and Organizations are global; their writes do not care which
region you name, and IAM changes propagate to regions eventually, not
instantly (see `waiters-and-timing.md`). Almost everything else is regional,
and some services are regional in ways that surprise: CloudTrail lookups
return the events of the queried region, so "no events" may mean "wrong
region", not "nothing happened"; S3 buckets have a home region even though
the namespace is global, and some operations require addressing it; ACM
certificates for CloudFront must live in `us-east-1` regardless of where the
distribution's origin runs. When a query about recent activity comes back
implausibly quiet, region is the first suspect.

## SCPs and permission boundaries: a denial is a finding

In an organization, the permissions a role's policy grants are the ceiling,
not the floor: service control policies, permission boundaries, and session
policies all subtract from it. Two consequences:

- **An `AccessDenied` under an SCP is information, not an obstacle.** It says
  the organization has decided this action does not happen in this account,
  or has decided it and forgotten to say so. Either way the response is the
  same: stop, capture the exact error and the denying policy if the message
  names it, and report it to whoever owns the guardrail. Never route around
  an organizational deny by switching to a different profile, a different
  role, or a different account until the call succeeds. That pattern,
  credential-shopping after a deny, is precisely what compromise looks like
  in a trail, and it converts a policy conversation into a security review of
  you.
- **Simulate before you conclude, and verify after you simulate.** The IAM
  policy simulator does not fully account for SCPs, so a clean simulation can
  still meet a live deny; treat the first real call as part of verification,
  per the mutation ladder. Conversely, a live deny on an action the role's
  own policy clearly allows is the signature of an SCP or boundary at work,
  name that in the finding rather than reporting "broken permissions".

The same posture applies to any organizational guardrail: region restrictions
enforced by SCP, mandatory-tag policies, disallowed services. Meeting one
means the map of what is permitted just got sharper. Update the plan, tell
the owner, and proceed inside the lines, not around them.
