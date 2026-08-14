# Cost and commitment

Most safety thinking about CLI operations centers on destruction: what gets
deleted, what goes down, what cannot be recovered. Spend is the blast radius
that thinking ignores. A command that commits the account to a year of
reserved capacity destroys nothing, breaks nothing, and pages nobody, yet it
can cost more than any outage the same operator will ever cause. The money is
gone (or committed) the moment the control plane accepts the request, and
unlike a deleted resource, there is often no snapshot to restore.

This is why the `sensitive` flag in the inventory includes spend commitments:
a financial commitment gets the same explicit human confirmation as a delete,
because it shares the property that matters, an irreversible consequence
hidden behind an ordinary-looking command that exits zero.

Two shapes of financial blast radius exist, and they fail differently.

## Long or irreversible commitments

These operations bind future spend with a single call. They succeed
instantly, look like any other `create` or `purchase` in the transcript, and
their cost arrives on invoices for months or years.

- **Reserved Instances and Savings Plans.** A purchase is a contract: one to
  three years of committed hourly spend, largely or entirely non-refundable.
  There is no delete verb that undoes it. `purchase-reserved-instances-offering`,
  `create-savings-plan`, and their siblings across services (RDS, ElastiCache,
  Redshift, OpenSearch reserved nodes) are the clearest case of a command
  whose blast radius is measured in currency, not resources.
- **Capacity Reservations.** On-Demand Capacity Reservations bill for the
  reserved capacity whether or not instances run in it. They are cancellable,
  which makes them gentler than an RI, but from the moment of creation the
  meter runs on empty capacity until someone remembers to release it.
- **Domain registration and renewal.** Registering a domain charges
  immediately and is generally non-refundable; auto-renew quietly converts a
  one-time decision into an annual one. Multi-year registrations multiply a
  typo into a multi-year bill.
- **Provisioned capacity.** DynamoDB provisioned throughput, Kinesis
  provisioned shards, provisioned concurrency on functions, provisioned IOPS
  on volumes: all bill for what is allocated, not what is used. Each is
  reversible in principle, but the cost accrues continuously from the moment
  of the call, and an over-provisioned table nobody revisits is a commitment
  in everything but name.
- **Always-on infrastructure.** NAT gateways, interface endpoints, load
  balancers, standing clusters, cross-zone standby replicas: resources that
  bill by the hour from creation, independent of traffic. None of these is
  large per hour; all of them are large per forgotten year. The commitment
  here is not contractual, it is inertial: the resource outlives the task
  that justified it.

The common trap is that the reversible members of this list (capacity
reservations, provisioned throughput, NAT gateways) feel safe because they
can be undone. They can, but only by a future action that has to be
remembered, owned, and executed. Treat "reversible but accruing" as committed
until the reversal is scheduled and attributable, which is what the tagging
discipline below is for.

## Runaway-scale actions

The second shape has no commitment at all; the cost is proportional to an
input the operator controls, and the failure mode is misjudging that input by
orders of magnitude. One command, correctly authorized, correctly formed,
producing a bill nobody intended.

- **Data egress and transfer.** Moving data out of the provider, across
  regions, or through a NAT gateway is billed per byte. A sync or copy of a
  large bucket, a restore pulled to the wrong region, a backup shipped over
  the internet path instead of a private one: the command is a one-liner, the
  cost is a function of the dataset size you may not have checked.
- **Cross-region replication.** Enabling replication on a bucket or table
  replicates the existing data and everything after it, paying transfer and
  storage on both sides indefinitely. It is a per-byte action dressed as a
  configuration change.
- **Unbounded analytical scans.** Athena bills per byte scanned; a query
  without partition predicates over a large table pays for the whole table,
  every run. Redshift Serverless and similar pay-per-compute engines have the
  same shape. A scheduled version of an unbounded query is a recurring
  charge that looks like a workflow.
- **Verbose log and metric ingestion.** Turning on debug-level logging, flow
  logs on a busy interface, data events in a trail, or high-cardinality
  custom metrics converts traffic volume into ingestion spend. These are
  classic "enabled for an incident, never disabled" costs; the enable is one
  command, the bill scales with someone else's traffic.
- **High-fan-out sends.** A publish, notify, or send looped over a large
  list multiplies per-message cost by the list length, and unlike the other
  items here it also spends reputation and recipient trust. The
  single-target-per-command rule from the mutation ladder applies to sends
  for financial reasons as well as safety ones.
- **Autoscaling ceiling raises.** Raising a group's maximum capacity costs
  nothing at the moment of the change; it grants a future event permission to
  spend. The command that raises max from 4 to 40 is the authorization for a
  10x bill that arrives later, under load, with the operator long gone from
  the session. Judge the change by the ceiling, not by the current count.

The audit-trail consequence is the same as for destructive bursts: a
runaway-cost event traced back to a session reads far better when that
session shows a stated purpose, a bounded input, and a checked estimate than
when it shows a bare command and a shrug.

## Rehearsing cost before committing

The mutation ladder's rehearsal rung applies to spend, and the tools exist;
they are just less habitual than `--dry-run`.

- **Use the rehearsal the service offers.** Skeleton and dry-run mechanics
  (`--generate-cli-skeleton`, `--dry-run` where the inventory marks support)
  validate the request; for commitments specifically, describe the offering
  before purchasing it. `describe-reserved-instances-offerings` and
  `savingsplans describe-savings-plans-offerings` return the exact price,
  term, and payment option of what a purchase call would buy. Reading the
  offering back, and stating its total cost, is the feasibility rung for a
  purchase.
- **Read the price with the read APIs.** The Pricing API
  (`aws pricing get-products`) answers "what does this configuration cost per
  hour/GB/request" before anything is created. Cost Explorer's read side
  (`ce get-cost-and-usage`, `ce get-cost-forecast`,
  `ce get-savings-plans-purchase-recommendation`) answers "what are we
  spending now and what would this change do to it". For scans, the engine
  itself often tells you: an `EXPLAIN`, a `LIMIT`-ed probe, or a query
  against a single partition establishes bytes-scanned per unit before the
  full run. A cost estimate stated in one sentence before the command is the
  spend equivalent of a change set review.
- **Tag every cost-bearing resource so spend is attributable and
  reversible.** The standard tag set (`tagging.md`) earns its keep here:
  `owner` makes the bill someone's, `purpose` explains it, and an
  expiry-style tag turns "reversible in principle" into "scheduled to be
  reversed". A NAT gateway tagged with an owner and an expiry is a bounded
  cost; the same gateway untagged is a permanent line item nobody feels
  responsible for. Cost allocation reports group by exactly these tags, so
  the tagging discipline is also what makes the spend reviewable at all.
- **Prefer the smallest reversible increment.** On-demand before reserved;
  a one-year no-upfront plan before a three-year all-upfront one; provisioned
  capacity sized to measured demand plus margin, not to peak imagination; a
  single-partition query before the full scan; a canary send before the full
  list; a modest autoscaling ceiling raised again later if reality asks for
  it. Commitments reward those who commit late, from data; the discount for
  committing early, from guesswork, is rarely worth the downside.

## Spend commitments are a confirmed sensitive class

Operationally, the rule is short. Any operation that purchases a term
commitment, registers or renews a domain, provisions standing paid capacity,
or plausibly triggers spend at a scale beyond the routine cost of the session
is treated as `sensitive`: before running it, state in one plain sentence
what it will cost, on what recurrence or term, and under whose authorization,
then obtain explicit human confirmation, exactly as you would for a destroy.

> Purchasing one 1-year no-upfront reserved offering for the standing
> database instance, approximately $X/month committed for 12 months,
> non-refundable, per the owning team's capacity decision.

If that sentence cannot be written, the cost is not understood, and a cost
that is not understood is not authorized. The confirmation is not
bureaucracy; it is the moment the financial blast radius gets chosen
deliberately, before the command, which is the only time it can be chosen
at all.
