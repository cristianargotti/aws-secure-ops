# Networking: secure operation patterns

## Services covered

- **elbv2** (Application/Network/Gateway Load Balancers): listeners, rules, target groups, trust stores. The workhorse of traffic entry.
- **elb** (Classic Load Balancer): legacy; instance-based registration and listener policies.
- **route53**: public and private hosted zones, record sets, health checks, DNSSEC, traffic policies.
- **route53domains**: domain registration, renewal, transfer locks, auth codes. Registrar-level actions are hard or impossible to undo.
- **route53resolver**: resolver endpoints, forwarding rules, DNS Firewall, query logging, cross-account sharing policies.
- **cloudfront**: distributions, origin access control, functions, key groups, invalidations, WAF association.
- **apigateway / apigatewayv2**: REST, HTTP, and WebSocket APIs, stages, authorizers, API keys, custom domains.
- **globalaccelerator**: static anycast IPs, listeners, endpoint groups, BYOIP advertisement.
- **network-firewall**: firewalls, firewall policies, rule groups, TLS inspection, flow operations.
- **networkmanager**: global networks, Cloud WAN core networks, policy versions, attachments.
- **directconnect**: physical connections, LAGs, virtual interfaces, BGP peers.
- **arc-zonal-shift / arc-region-switch / route53-recovery-cluster / route53-recovery-control-config / route53-recovery-readiness**: Application Recovery Controller. These commands move live production traffic; treat every state change as a failover action.
- **vpc-lattice**: service networks, services, auth policies, target groups.
- **servicediscovery** (Cloud Map): namespaces, services, instance registration.

Long tail: appmesh (deprecated service mesh), apigatewaymanagementapi (WebSocket post/delete to live connections), cloudfront-keyvaluestore, networkflowmonitor, networkmonitor, route53profiles, route53-recovery-readiness.

## Querying safely

Always bound list calls. Prefer server-side filters, then `--query` for projection, then `--max-items` as a ceiling.

```bash
# Load balancers: name-scoped, projected
aws elbv2 describe-load-balancers --names my-alb \
  --query 'LoadBalancers[].{DNS:DNSName,State:State.Code,Scheme:Scheme}'
aws elbv2 describe-target-health --target-group-arn "$TG_ARN" \
  --query 'TargetHealthDescriptions[].{Id:Target.Id,State:TargetHealth.State,Reason:TargetHealth.Reason}'
aws elbv2 describe-listeners --load-balancer-arn "$LB_ARN" \
  --query 'Listeners[].{Port:Port,Proto:Protocol,Cert:Certificates[0].CertificateArn}'

# Route 53: name-anchored record listing, never a full-zone dump
aws route53 list-resource-record-sets --hosted-zone-id "$ZONE_ID" \
  --start-record-name app.example.com --start-record-type A --max-items 20
aws route53 list-hosted-zones-by-name --dns-name example.com --max-items 5

# CloudFront: project the fields you need, cap the page
aws cloudfront list-distributions --query \
  "DistributionList.Items[?Aliases.Items[0]=='www.example.com'].{Id:Id,Domain:DomainName,Status:Status}"
aws cloudfront get-distribution-config --id "$DIST_ID" \
  --query 'DistributionConfig.{Aliases:Aliases,WebACL:WebACLId,Enabled:Enabled}'

# API Gateway: one API at a time
aws apigatewayv2 get-apis --max-items 25 --query 'Items[].{Id:ApiId,Name:Name,Proto:ProtocolType}'
aws apigateway get-stages --rest-api-id "$API_ID" \
  --query 'item[].{Stage:stageName,Deploy:deploymentId,Logs:accessLogSettings.destinationArn}'

# Network Firewall / resolver: scoped describes
aws network-firewall describe-firewall --firewall-name my-fw \
  --query 'FirewallStatus.{Status:Status,Sync:ConfigurationSyncStateSummary}'
aws route53resolver list-resolver-rules --max-items 50 \
  --query 'ResolverRules[].{Id:Id,Domain:DomainName,Type:RuleType}'
```

Credential-emitting reads that require explicit purpose: `apigateway get-api-key --include-value` and `get-api-keys --include-values` return live API key values; `get-usage-plan-key(s)` responses include key values; `route53domains retrieve-domain-auth-code` returns the code that authorizes a registrar transfer. Never log or paste these outputs. Omit `--include-value` unless the value itself is the task.

## Mutating safely

No networking service in this domain offers `--dry-run`. Compensate with staged flows, read-before-write, and one target per command.

- **Read-modify-write for versioned configs.** CloudFront and API Gateway configs are replaced whole. Fetch the current config, edit the JSON locally, then submit with the returned `ETag`/version: `aws cloudfront get-distribution-config --id X` then `update-distribution --if-match "$ETAG"`. A stale ETag fails safely; never bypass it.
- **Route 53 changes are transactional batches.** Build the change batch in a file, review it, submit once: `aws route53 change-resource-record-sets --hosted-zone-id Z --change-batch file://change.json`. Prefer `UPSERT` over `DELETE`+`CREATE`. Capture the returned change Id for the waiter. To modify weighted or failover sets, target the exact `SetIdentifier`.
- **CloudFront staging distributions are the changeset flow.** `copy-distribution` to a staging copy, test it, then `update-distribution-with-staging-config` to promote. Use this for any risky distribution change.
- **Cloud WAN policies are staged natively.** `networkmanager put-core-network-policy` only stores a version; review with `get-core-network-change-set`, then apply with `execute-core-network-change-set`. Never skip the change-set review.
- **API Gateway stages decouple config from traffic.** Changes to REST resources do nothing until `create-deployment` points a stage at them. Deploy to a non-production stage first. `put-rest-api` and `apigatewayv2 reimport-api` with overwrite semantics replace the whole API definition, including authorizers: diff the exported spec (`get-export` / `export-api`) against the new one before importing.
- **Tag at creation.** Most services accept `--tags` inline: `aws elbv2 create-load-balancer ... --tags Key=env,Value=prod Key=owner,Value=team`, `aws cloudfront create-distribution-with-tags`, `aws route53 change-tags-for-resource --resource-type hostedzone`. VPC Lattice, Network Firewall, and Global Accelerator all take `--tags` on create.
- **One target per command.** Deregister one target, delete one rule, change one record batch per invocation. Never loop a delete over an unreviewed list.
- **Exposure boundaries need documented intent**: `put-resource-policy` (network-firewall, networkmanager, cloudfront, vpc-lattice), `vpc-lattice put-auth-policy`, resolver sharing policies (`put-resolver-rule-policy`, `put-firewall-rule-group-policy`, `put-resolver-query-log-config-policy`), `route53 create-vpc-association-authorization`, and `elbv2 set-security-groups` all widen who can reach or manage the resource. State the principal and the reason before running them.

## Destructive traps

| Command                                                                            | Why dangerous                                                                                     | Safe procedure                                                                                      |
| ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `route53 change-resource-record-sets` (DELETE action)                              | Deleting or mistyping a live record blackholes traffic instantly; values must match exactly       | Export the current record first, use UPSERT where possible, keep the pre-change JSON as rollback    |
| `route53 delete-hosted-zone`                                                       | Zone gone means NXDOMAIN for every name in it; delegation still points at dead servers            | Confirm zero non-default records, export zone to file, verify no NS delegation still resolves to it |
| `route53domains push-domain` / `transfer-domain-to-another-aws-account`            | Moves the domain out of the account or registrar; the transfer response emits a one-time password | Human confirmation, verify destination account/registrar, treat the password as a secret            |
| `route53domains disable-domain-transfer-lock`                                      | Unlocked domains can be transferred away (hijack precondition)                                    | Unlock only for an imminent, verified transfer; re-enable immediately after                         |
| `route53 disable-hosted-zone-dnssec` / `deactivate-key-signing-key`                | If the DS record still exists at the parent, resolvers mark the zone bogus: total outage          | Remove the DS record at the parent and wait out its TTL before disabling signing                    |
| `elbv2 delete-load-balancer` / `delete-listener` / `delete-target-group`           | Immediately stops serving traffic; DNS clients may cache the LB name for minutes                  | Verify nothing resolves to it, drain targets first, delete listener before LB only when intended    |
| `elbv2 deregister-targets` / `elb deregister-instances-from-load-balancer`         | Removes capacity from a live pool; draining still severs long-lived connections at timeout        | Deregister one batch, wait for `target-deregistered`, confirm remaining healthy capacity            |
| `elbv2 set-security-groups`                                                        | Replaces (not appends) the SG list; a wrong list cuts all traffic or opens exposure               | Read current SGs, submit the full intended list, re-read and connectivity-test after                |
| `cloudfront delete-distribution`                                                   | Removes the edge entry point; aliases stop serving; requires disable first                        | Disable, wait for `distribution-deployed`, confirm no traffic in metrics, then delete with ETag     |
| `cloudfront disassociate-distribution-web-acl`                                     | Silently removes the WAF layer from a public distribution                                         | Treat as an exposure change: documented approval, re-associate window planned                       |
| `apigateway delete-stage` / `delete-rest-api` / `apigatewayv2 delete-api`          | Kills the invoke URL for every client at once                                                     | Confirm stage traffic is zero (CloudWatch), export the API spec as backup first                     |
| `arc-zonal-shift start-zonal-shift` / `arc-region-switch start-plan-execution`     | Moves live production traffic between AZs or Regions on purpose                                   | Incident-context only, human confirmation, set a short `--expires-in`, know the cancel command      |
| `route53-recovery-cluster update-routing-control-state`                            | Turning a control OFF stops traffic to a cell; bypassing safety rules can fail everything closed  | Never use `--safety-rules-to-override` casually; verify target cell health before flipping          |
| `network-firewall delete-firewall` / `disassociate-firewall-policy`                | Removes traffic inspection; depending on routing, traffic drops or flows unfiltered               | Check `DeleteProtection` and subnet route tables; update routes before touching the firewall        |
| `network-firewall start-flow-flush`                                                | Prunes established flows; active connections break as midstream traffic                           | Scope the flow filters narrowly, run in a maintenance window                                        |
| `globalaccelerator withdraw-byoip-cidr` / `deprovision-byoip-cidr`                 | Withdraws the BGP advertisement; anything using those IPs goes dark internet-wide                 | Confirm no accelerator or DNS name still uses the range; advertise elsewhere first if migrating     |
| `directconnect delete-connection` / `delete-virtual-interface` / `delete-bgp-peer` | Severs private connectivity to on-premises; physical re-provisioning takes weeks                  | Confirm redundant path is up (BGP established) before deleting either side                          |
| `directconnect start-bgp-failover-test`                                            | Deliberately takes the BGP session down; without a healthy second path this is an outage          | Verify the redundant VIF is Established, bound the test with `--test-duration-in-minutes`           |
| `servicediscovery deregister-instance` / `delete-service`                          | Consumers resolving via Cloud Map stop finding the backend                                        | Deregister instances one at a time, confirm remaining instance count covers load                    |
| `apigatewaymanagementapi delete-connection`                                        | Force-closes a live WebSocket client                                                              | Target a single verified connection Id only                                                         |

## Waiters and timing

Available waiters (delay x attempts = max wait):

| Service                         | Waiter                                                    | Delay x attempts | Max wait | Polls                    |
| ------------------------------- | --------------------------------------------------------- | ---------------- | -------- | ------------------------ |
| elbv2                           | load-balancer-available                                   | 15s x 40         | 10 min   | describe-load-balancers  |
| elbv2                           | load-balancers-deleted                                    | 15s x 40         | 10 min   | describe-load-balancers  |
| elbv2                           | target-in-service / target-deregistered                   | 15s x 40         | 10 min   | describe-target-health   |
| elb                             | instance-in-service / instance-deregistered               | 15s x 40         | 10 min   | describe-instance-health |
| route53                         | resource-record-sets-changed                              | 30s x 60         | 30 min   | get-change               |
| cloudfront                      | distribution-deployed                                     | 60s x 35         | 35 min   | get-distribution         |
| cloudfront                      | invalidation-completed                                    | 20s x 30         | 10 min   | get-invalidation         |
| route53-recovery-control-config | cluster/control-panel/routing-control created and deleted | 5s x 26          | ~2 min   | describe-*               |
| arc-region-switch               | plan-execution-completed                                  | 30s x 5          | 2.5 min  | get-plan-execution       |

```bash
aws route53 wait resource-record-sets-changed --id "$CHANGE_ID"
aws elbv2 wait target-in-service --target-group-arn "$TG_ARN" --targets Id="$TARGET"
aws cloudfront wait distribution-deployed --id "$DIST_ID"
```

Where no waiter exists, poll a bounded status field with an explicit iteration cap (for example, 20 polls at 15s, then stop and report):

- Network Firewall: `describe-firewall --query 'FirewallStatus.Status'` until `READY`, and `ConfigurationSyncStateSummary` until `IN_SYNC`.
- Global Accelerator: `describe-accelerator --query 'Accelerator.Status'` until `DEPLOYED`.
- VPC Lattice: `get-service-network-vpc-association --query 'status'` until `ACTIVE`.
- NetworkManager: `get-core-network-change-events` until the change set reports executed.
- API Gateway custom domains: `get-domain-name --query 'domainNameStatus'` until `AVAILABLE`.
- Direct Connect: `describe-virtual-interfaces --query '...bgpPeers[].bgpStatus'` until `up`.
- Route 53 Resolver: `get-resolver-endpoint --query 'ResolverEndpoint.Status'` until `OPERATIONAL`.
- Zonal shift: `list-zonal-shifts --status ACTIVE` to confirm the shift is in effect or expired.

Never poll in an unbounded loop, and never tighten a loop below the waiter's native delay.

## Verification after change

Prove the mutation landed with a read-back, then prove the data plane agrees:

```bash
# Route 53: change status plus a live answer
aws route53 get-change --id "$CHANGE_ID" --query 'ChangeInfo.Status'   # INSYNC
aws route53 test-dns-answer --hosted-zone-id "$ZONE_ID" \
  --record-name app.example.com --record-type A

# ELBv2: config and health
aws elbv2 describe-listeners --load-balancer-arn "$LB_ARN" \
  --query 'Listeners[].{Port:Port,Default:DefaultActions[0].Type}'
aws elbv2 describe-target-health --target-group-arn "$TG_ARN" \
  --query 'TargetHealthDescriptions[].TargetHealth.State'

# CloudFront: status Deployed and the intended config field
aws cloudfront get-distribution --id "$DIST_ID" \
  --query 'Distribution.{Status:Status,Enabled:DistributionConfig.Enabled,ACL:DistributionConfig.WebACLId}'
aws cloudfront verify-dns-configuration --domain www.example.com   # read-only check

# API Gateway: the stage points at the new deployment
aws apigateway get-stage --rest-api-id "$API_ID" --stage-name prod --query 'deploymentId'

# Network Firewall: policy in sync across zones
aws network-firewall describe-firewall --firewall-name my-fw \
  --query 'FirewallStatus.ConfigurationSyncStateSummary'

# Exposure changes: read the policy back verbatim
aws vpc-lattice get-auth-policy --resource-identifier "$SN_ID"
aws network-firewall describe-resource-policy --resource-arn "$ARN"

# Recovery controls: confirm the state you set
aws route53-recovery-cluster get-routing-control-state \
  --routing-control-arn "$RC_ARN" --region "$CLUSTER_REGION"
```

After any exposure-boundary change (resource policy, auth policy, sharing policy, security groups, WAF association), read the full document back and diff it against the intended version; a partial or merged policy is a silent failure. After any traffic-shifting change (zonal shift, routing control, weighted records), verify with data-plane evidence (health checks, request metrics), not just the control-plane status.
