# Platform and miscellaneous services: secure operation patterns

This domain covers the long tail: IoT, media, end-user computing, marketplace, billing adjuncts, and specialty platforms. Apply the core taxonomy strictly; the traps below are where these services deviate from intuition.

## Services covered

Largest fifteen by operation count, with the one safety note that matters most:

| Service                  | Note                                                                                                   |
| ------------------------ | ------------------------------------------------------------------------------------------------------ |
| iot                      | `create-keys-and-certificate` emits a private key once; certificate transfer crosses accounts          |
| medialive                | stop/delete on a running channel interrupts live output; input security groups are an ingress boundary |
| gamelift                 | `get-compute-access` and `request-upload-credentials` return live credentials                          |
| deadline                 | farm/fleet deletes cancel running render jobs; member associations are access grants                   |
| iotwireless              | partner-account association links to an external account                                               |
| iotsitewise              | asset model updates propagate to every asset built from the model                                      |
| customer-profiles        | domain deletion removes all profiles; treat as data destruction                                        |
| greengrass               | `reset-deployments` clears device deployments fleet-wide                                               |
| workmail                 | `reset-password` and mailbox permissions are account-takeover vectors                                  |
| workspaces               | terminate destroys user data with no recycle bin; ip-rules gate desktop reachability                   |
| appstream                | streaming URLs are bearer credentials; image permissions share across accounts                         |
| iot-managed-integrations | credential lockers hold device secrets; deletes orphan onboarded devices                               |
| mediaconnect             | `grant-flow-entitlements` grants another account subscription rights                                   |
| devicefarm               | remote access sessions bill per device minute; stop sessions when done                                 |
| workspaces-web           | associate/disassociate of settings changes what live portals enforce                                   |

Long tail (same rules apply): aiops, amp, appsync, artifact, autoscaling-plans, b2bi, billing, billingconductor, braket, chatbot, cloud9, clouddirectory, cloudsearch, codeartifact, devops-guru, discovery, dlm, elastictranscoder, finspace, gamelift-streams, grafana, greengrassv2, groundstation, iotevents, iotsecuretunneling, ivs family, m2, managedblockchain, marketplace family, mediaconvert, mediapackage family, mediastore, mediatailor, meteringmarketplace, mturk, osis, pcs, pi, rbin, repostspace, savingsplans, schemas, securitylake, signin, taxsettings, tnb, transfer, voice-id, wellarchitected, workdocs.

## Querying safely

Always bound reads. These services default to large pages and some paginate poorly.

```bash
aws iot list-things --max-items 50 --query 'things[].{name:thingName,type:thingTypeName}'
aws iot list-certificates --max-items 50 --query 'certificates[].{id:certificateId,status:status}'
aws medialive list-channels --max-items 20 --query 'Channels[].{Id:Id,State:State,Name:Name}'
aws medialive describe-channel --channel-id <id> --query '{State:State,Pipelines:PipelineDetails}'
aws workspaces describe-workspaces --limit 25 --query 'Workspaces[].{Id:WorkspaceId,State:State,User:UserName}'
aws transfer list-servers --max-items 20 --query 'Servers[].{Id:ServerId,State:State,EndpointType:EndpointType}'
aws gamelift describe-fleet-attributes --query 'FleetAttributes[].{Id:FleetId,Status:Status}'
aws appstream describe-fleets --query 'Fleets[].{Name:Name,State:State}'
aws codeartifact list-repositories --max-items 50 --query 'repositories[].{name:name,domain:domainName}'
```

Prefer server-side filters where they exist (`--thing-type-name`, `--target-arn`, `--status`) over client-side `--query` filtering of full dumps. Never run an unfiltered `list-*` against IoT fleets or customer-profiles domains; these can return tens of thousands of items.

Reads that emit secrets are not routine reads. Treat these as credential retrieval requiring the same purpose stamp as a mutation: `iot describe-certificate` (public cert only, acceptable), but `gamelift get-compute-access`, `finspace-data get-programmatic-access-credentials`, `finspace get-kx-connection-string`, `ivs get-stream-key`, `managedblockchain get-accessor`, `route53globalresolver get-access-token`, and `appsync list-api-keys` all return usable credential material in the response.

## Mutating safely

- Almost nothing in this domain supports `--dry-run`. Substitute a read of the exact target immediately before the mutation, and paste the read output into the change record.
- One target per command. Avoid `batch-*` mutation variants unless the batch is the unit of intent (for example `batch-meter-usage` with a prepared record set).
- Tag at creation time; most services accept `--tags` on create: `--tags Key=purpose,Value=<ticket> Key=owner,Value=<team>` (shorthand varies: some take `key=value` maps such as `--tags purpose=<ticket>`; check `aws SERVICE OPERATION help` first).
- Staged flows exist in a few places, use them: MediaLive signal maps deploy monitors via explicit `start-*-monitor-deployment`; TNB separates create (register) from instantiate; marketplace-catalog batches edits into change sets (`start-change-set`) that can be described before they apply.
- Config-attach services (workspaces-web, appstream, iotsitewise portals) change live behavior at associate/disassociate time, not at create time. Creating a settings object is safe; associating it is the real mutation.

## Destructive traps

| Command                                                  | Why dangerous                                                | Safe procedure                                                              |
| -------------------------------------------------------- | ------------------------------------------------------------ | --------------------------------------------------------------------------- |
| `workspaces terminate-workspaces`                        | Destroys the user volume permanently, no recovery            | Confirm user offboarded, snapshot data if needed, one workspace per call    |
| `iot update-certificate --new-status REVOKED/INACTIVE`   | Silently disconnects every device using the cert             | List things attached to the cert first, stage on one device                 |
| `iot delete-thing` / `delete-certificate --force-delete` | Force flag bypasses attachment checks                        | Detach policies and principals explicitly, then delete without force        |
| `medialive stop-channel` / `delete-channel`              | Kills live broadcast output instantly                        | Verify channel is not serving production viewers, check schedule first      |
| `mediapackagev2 reset-channel-state`                     | Interrupts active playback sessions                          | Treat as an outage action, coordinate a maintenance window                  |
| `codeartifact dispose-package-versions`                  | Assets deleted, version can never be restored                | Prefer `delete-package-versions` (restorable) unless disposal is the intent |
| `transfer start-remote-delete`                           | Deletes files on the remote partner SFTP server              | Confirm remote path with the partner, list directory first                  |
| `discovery start-batch-delete-configuration-task`        | Bulk-erases collected discovery data asynchronously          | Export data first, verify the configurationId list twice                    |
| `greengrass reset-deployments`                           | Wipes deployment state for the whole group                   | Capture current deployment id, confirm devices tolerate reset               |
| `customer-profiles delete-domain`                        | Removes all profiles and integrations in the domain          | Enumerate object types and integrations first, export if retention applies  |
| `savingsplans return-savings-plan`                       | Cancels a purchased financial commitment                     | Finance approval before execution, verify plan id against billing           |
| `mturk create-hit` / `send-bonus` / `approve-assignment` | Publishes to a public workforce and spends real money        | Verify reward amounts and sandbox-test the HIT template first               |
| `iotsecuretunneling close-tunnel`                        | Permanently ends the tunnel, drops remote access mid-session | Confirm no active operator session, note tunnel cannot be reopened          |
| `dlm delete-lifecycle-policy`                            | Managed snapshots stop; retention cleanup may still run      | Review policy state and retained snapshot inventory before deleting         |

## Waiters and timing

Use the built-in waiters; poll manually only when none exists, always with a bounded loop.

| Waiter                                    | Delay x attempts | Max wait |
| ----------------------------------------- | ---------------- | -------- |
| medialive channel-running                 | 5s x 120         | 10 min   |
| medialive channel-stopped                 | 5s x 60          | 5 min    |
| medialive channel-deleted                 | 5s x 84          | 7 min    |
| medialive input-detached                  | 5s x 84          | 7 min    |
| mediaconnect flow-active / flow-deleted   | 3s x 40          | 2 min    |
| appstream fleet-started / fleet-stopped   | 30s x 40         | 20 min   |
| transfer server-online / server-offline   | 30s x 120        | 60 min   |
| iotsitewise asset-model-active            | 3s x 20          | 1 min    |
| deadline fleet-active                     | 5s x 180         | 15 min   |
| gameliftstreams stream-group-active       | 30s x 120        | 60 min   |
| repostspace space-created / space-deleted | 300s x 24        | 120 min  |
| elastictranscoder job-complete            | 30s x 120        | 60 min   |
| amp workspace-active / workspace-deleted  | 2s x 60          | 2 min    |

Example: `aws medialive wait channel-stopped --channel-id <id>`. Where no waiter exists (iot, workspaces, workmail, codeartifact), poll the corresponding describe/get with the status field in `--query`, sleep 10 to 30 seconds between attempts, and cap at a fixed attempt count; never loop unbounded. WorkSpaces terminations can take up to an hour to leave `TERMINATING`; check once, then re-check on a schedule instead of blocking.

## Verification after change

Read back the exact object mutated, not the list.

```bash
aws iot describe-certificate --certificate-id <id> --query 'certificateDescription.status'
aws iot list-attached-policies --target <cert-arn>          # after attach/detach
aws medialive describe-channel --channel-id <id> --query 'State'
aws workspaces describe-workspaces --workspace-ids <id> --query 'Workspaces[0].State'
aws transfer describe-server --server-id <id> --query 'Server.State'
aws appstream describe-image-permissions --name <image>      # after sharing changes
aws codeartifact get-repository-permissions-policy --domain <d> --repository <r>
aws workmail list-mailbox-permissions --organization-id <org> --entity-id <user>
aws mediaconnect describe-flow --flow-arn <arn> --query 'Flow.Entitlements'
aws grafana describe-workspace-authentication --workspace-id <id>
```

For exposure changes (policies, shares, entitlements, image permissions), read the policy document back and diff it against the intended document before closing the change record. For credential rotations, confirm the old credential is rejected, not merely that the new one works.
