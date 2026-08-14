# Compute: secure operation patterns

## Services covered

- **ec2**: instances, volumes, snapshots, AMIs, security groups, VPC networking primitives. Largest surface in this domain (749 operations), most mutations support `--dry-run`.
- **autoscaling**: Auto Scaling groups, launch configurations, lifecycle hooks, instance refresh. Capacity changes terminate instances by design.
- **lambda**: functions, versions, aliases, event source mappings, layers, function URLs, resource policies.
- **batch**: compute environments, job queues, job definitions, job submission and termination.
- **lightsail**: bundled VPS, databases, buckets, load balancers, container services. Several operations emit credential material.
- **elasticbeanstalk**: applications, environments, platform versions, CNAME swaps.
- **apprunner**: managed container services, deployments, VPC connectors.
- **imagebuilder**: image pipelines, recipes, components, cross-account distribution.
- Long tail: **ec2-instance-connect** (grants temporary SSH access), **outposts** (physical rack orders and decommission), **serverlessrepo** (application sharing policies).

## Querying safely

Always bound reads: server-side filters first, then `--query` to trim the payload, then `--max-items` to cap volume. Never dump a whole region's inventory into the transcript.

```bash
# EC2: filter server-side, project client-side
aws ec2 describe-instances \
  --filters "Name=tag:Project,Values=myproj" "Name=instance-state-name,Values=running" \
  --query 'Reservations[].Instances[].{Id:InstanceId,Type:InstanceType,AZ:Placement.AvailabilityZone,State:State.Name}' \
  --max-items 50

# Single resource by id, never by scan
aws ec2 describe-instances --instance-ids i-0123456789abcdef0 \
  --query 'Reservations[0].Instances[0].State'

aws ec2 describe-security-groups --group-ids sg-0123456789abcdef0 \
  --query 'SecurityGroups[0].IpPermissions'

# Snapshots and images: always scope to self, never to all
aws ec2 describe-snapshots --owner-ids self --max-items 50 \
  --query 'Snapshots[].{Id:SnapshotId,State:State,Enc:Encrypted}'
aws ec2 describe-images --owners self \
  --query 'Images[].{Id:ImageId,Name:Name,Public:Public}'

# Lambda
aws lambda list-functions --max-items 50 \
  --query 'Functions[].{Name:FunctionName,Runtime:Runtime,Updated:LastModified}'
aws lambda get-function-configuration --function-name my-fn \
  --query '{State:State,LastUpdateStatus:LastUpdateStatus,Version:Version}'

# Auto Scaling
aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names my-asg \
  --query 'AutoScalingGroups[0].{Min:MinSize,Max:MaxSize,Desired:DesiredCapacity,Healthy:length(Instances[?HealthStatus==`Healthy`])}'

# Batch: list only what is running in one queue
aws batch list-jobs --job-queue my-queue --job-status RUNNING --max-items 50 \
  --query 'jobSummaryList[].{Id:jobId,Name:jobName}'

# Lightsail
aws lightsail get-instances --query 'instances[].{Name:name,State:state.name,Ip:publicIpAddress}'
```

Reads that emit secrets pass the read gate but still require confirmation and must never land in logs: `ec2 get-password-data`, `lightsail get-instance-access-details`, `lightsail download-default-key-pair`, `lightsail get-relational-database-master-user-password`, `lightsail get-bucket-access-keys`.

## Mutating safely

**Dry-run first on EC2.** Most `ec2` mutations accept `--dry-run`, which validates permissions and parameters without executing. Expect `DryRunOperation` on success, `UnauthorizedOperation` on a permissions gap:

```bash
aws ec2 terminate-instances --instance-ids i-0123456789abcdef0 --dry-run
aws ec2 authorize-security-group-ingress --group-id sg-012345 \
  --ip-permissions 'IpProtocol=tcp,FromPort=443,ToPort=443,IpRanges=[{CidrIp=10.0.0.0/8}]' --dry-run
```

`autoscaling`, `lambda`, `batch`, `lightsail`, `elasticbeanstalk`, and `apprunner` have no dry-run: state intent explicitly, mutate one target, verify, then proceed.

**Staged flows instead of in-place edits:**

- EC2 launch changes: create a new launch template version, validate it, then point the ASG at it. Roll back by re-pinning the previous version number.
- Lambda: publish a version (`publish-version`), shift traffic with an alias (`update-alias --routing-config`), keep `$LATEST` out of production event sources.
- Auto Scaling fleet replacement: `start-instance-refresh` with `MinHealthyPercentage` set, monitor with `describe-instance-refreshes`, abort with `cancel-instance-refresh`.
- Elastic Beanstalk: deploy to a parallel environment, verify health `Green`, then swap CNAMEs. The swap itself redirects production traffic and requires confirmation.
- Image Builder: test a recipe through a manual `start-image-pipeline-execution` before enabling the pipeline schedule.

**Tag at creation time**, never as a follow-up call that can be forgotten:

```bash
aws ec2 run-instances ... --tag-specifications \
  'ResourceType=instance,Tags=[{Key=Project,Value=myproj},{Key=Owner,Value=team}]' \
  'ResourceType=volume,Tags=[{Key=Project,Value=myproj}]'
aws lambda create-function ... --tags Project=myproj,Owner=team
aws autoscaling create-auto-scaling-group ... \
  --tags 'Key=Project,Value=myproj,PropagateAtLaunch=true'
aws lightsail create-instances ... --tags key=Project,value=myproj
```

**One target per command.** `terminate-instances`, `stop-instances`, `delete-fleets`, `cancel-spot-fleet-requests`, and `batch-delete-scheduled-action` all accept lists. Pass exactly one id per invocation so a wrong id costs one resource, not a fleet.

**Credential-emitting mutations**: `ec2 create-key-pair` and `lightsail create-key-pair` return the private key exactly once, `lightsail create-bucket-access-key` returns the secret key once, `lightsail create-container-service-registry-login` returns temporary registry credentials. Write the material straight to a protected file (`--query ... --output text > key.pem && chmod 600 key.pem`), never echo it. Prefer `import-key-pair` (public key only) over `create-key-pair` where possible.

## Destructive traps

| Command                                                                          | Why dangerous                                                                                        | Safe procedure                                                                                                     |
| -------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `ec2 terminate-instances`                                                        | Irreversible; instance-store data lost; EBS volumes with DeleteOnTermination go with it              | Check `disableApiTermination` and volume mappings, dry-run, one instance id, confirm, waiter `instance-terminated` |
| `ec2 delete-volume` / `delete-snapshot`                                          | Data destruction; snapshot may back an AMI or be the only copy                                       | Verify volume is `available` (detached), verify no AMI references the snapshot, snapshot before deleting a volume  |
| `ec2 deregister-image`                                                           | AMIs used by ASG launch templates break future scale-out silently                                    | Grep launch templates and ASGs for the AMI id first; keep the backing snapshot until confirmed                     |
| `ec2 revoke-security-group-ingress` / `delete-security-group`                    | Cuts live traffic; deletion fails silently in scripts if still attached                              | Describe rules first, revoke one rule at a time, confirm no ENI references the group before delete                 |
| `ec2 modify-image-attribute` / `modify-snapshot-attribute`                       | `--launch-permission`/`--create-volume-permission` with group `all` makes the AMI or snapshot public | Grant to explicit account ids only; verify with `describe-image-attribute`; keep block-public-access enabled       |
| `ec2 disable-image-block-public-access` / `disable-snapshot-block-public-access` | Removes the account-level guardrail against public AMIs and snapshots                                | Treat as an exposure change: confirm, time-box, re-enable, verify state                                            |
| `autoscaling set-desired-capacity` / `update-auto-scaling-group`                 | Any decrease terminates instances immediately per termination policy                                 | Read current Min/Desired/Max first, step down gradually, use instance protection on pets                           |
| `autoscaling delete-auto-scaling-group --force-delete`                           | Terminates every instance in the group without draining                                              | Scale to 0 first, wait for drain, then delete without `--force-delete`                                             |
| `lambda delete-function`                                                         | Deletes all versions and aliases; event sources start failing instantly                              | List event source mappings and aliases first, disable mappings, delete one qualifier at a time if versions must go |
| `lambda add-permission` / `create-function-url-config`                           | Resource policy grant; URL with `--auth-type NONE` is a public unauthenticated endpoint              | Grant a single principal with `--source-arn`; default to `AWS_IAM` auth on URLs; read back the policy              |
| `lambda put-function-concurrency --reserved-concurrent-executions 0`             | Throttles the function to zero, a full outage that looks like a config tweak                         | Confirm intent explicitly; record previous value for rollback                                                      |
| `batch terminate-job` / `delete-compute-environment`                             | Kills running work; deleting the environment strands its queues                                      | Cancel queued jobs first, disable the compute environment, wait for `state=DISABLED`, then delete                  |
| `elasticbeanstalk rebuild-environment`                                           | Deletes and recreates all environment resources, full outage                                         | Prefer a parallel environment plus CNAME swap; rebuild only on explicit confirmation                               |
| `elasticbeanstalk swap-environment-cnames`                                       | Instantly redirects production traffic between environments                                          | Verify target environment health is `Green` and `Ready` first; have the reverse swap ready                         |
| `lightsail stop-instance` / `delete-instance`                                    | Stop releases the dynamic public IP (DNS breaks); delete is final                                    | Attach a static IP before stopping; snapshot (`create-instance-snapshot`) before deleting                          |
| `ec2-instance-connect send-ssh-public-key`                                       | Grants 60 seconds of SSH access with any supplied key, an access grant disguised as a push           | Use only for your own audited session; never run with a key you did not just generate                              |
| `outposts start-outpost-decommission`                                            | Begins physical return of racks or servers                                                           | Management chain approval outside the CLI session; verify no capacity remains in use                               |
| `serverlessrepo put-application-policy`                                          | Can share an application with every AWS account (public)                                             | Grant explicit account ids; read back with `get-application-policy`                                                |

## Waiters and timing

Built-in waiters (`aws <svc> wait <name>`), delay x attempts = max wait:

- **ec2**: `instance-running`, `instance-stopped`, `instance-terminated`, `instance-status-ok`, `system-status-ok`, `snapshot-completed`, `image-available`, `volume-available`, `volume-deleted`, `nat-gateway-available`, `nat-gateway-deleted`, `vpn-connection-available`: all 15s x 40 = 10 min. `instance-exists` 5s x 40 = 200s. `password-data-available` 15s x 40 = 10 min. Existence probes are short: `security-group-exists`, `key-pair-exists`, `internet-gateway-exists` 5s x 6 = 30s; `vpc-exists` 1s x 5 = 5s. `network-interface-available` 20s x 10 = 200s.
- **elasticbeanstalk**: `environment-exists`, `environment-updated`, `environment-terminated`: 20s x 20 = 400s.
- **lambda**: `function-exists` 1s x 20 = 20s; `function-active` / `function-updated` 5s x 60 = 5 min (v2 variants 1s x 300); `published-version-active` 5s x 312 = 26 min.

```bash
aws ec2 wait instance-stopped --instance-ids i-0123456789abcdef0
aws lambda wait function-updated --function-name my-fn
```

No waiter exists for: autoscaling activities, batch jobs, apprunner operations, lightsail operations, imagebuilder builds, instance refresh. Poll the status API on a bounded loop (fixed interval, hard attempt cap, then stop and report):

```bash
# Auto Scaling instance refresh, max 30 x 30s = 15 min
for i in $(seq 1 30); do
  S=$(aws autoscaling describe-instance-refreshes --auto-scaling-group-name my-asg \
      --max-records 1 --query 'InstanceRefreshes[0].Status' --output text)
  [ "$S" = Successful ] && break
  [ "$S" = Failed ] || [ "$S" = Cancelled ] && { echo "$S"; exit 1; }
  sleep 30
done

# Batch job, cap attempts the same way
aws batch describe-jobs --jobs "$JOB_ID" --query 'jobs[0].status' --output text

# App Runner operation
aws apprunner list-operations --service-arn "$ARN" --max-results 1 \
  --query 'OperationSummaryList[0].Status'

# Lightsail async operations
aws lightsail get-operation --operation-id "$OP_ID" --query 'operation.status'
```

Never poll without an attempt cap, and never tighten the interval below the service's own waiter cadence.

## Verification after change

Prove every mutation landed with a targeted read-back, not by absence of an error:

```bash
# Instance lifecycle
aws ec2 describe-instances --instance-ids i-0123456789abcdef0 \
  --query 'Reservations[0].Instances[0].State.Name'

# Security group rule landed, and nothing else changed
aws ec2 describe-security-groups --group-ids sg-012345 \
  --query 'SecurityGroups[0].IpPermissions'

# AMI or snapshot is NOT public after attribute work
aws ec2 describe-image-attribute --image-id ami-012345 --attribute launchPermission
aws ec2 describe-snapshot-attribute --snapshot-id snap-012345 --attribute createVolumePermission

# Block-public-access guardrails still on
aws ec2 get-image-block-public-access-state
aws ec2 get-snapshot-block-public-access-state

# Lambda: config, policy, and URL exposure
aws lambda get-function-configuration --function-name my-fn \
  --query '{State:State,Status:LastUpdateStatus,Sha:CodeSha256}'
aws lambda get-policy --function-name my-fn --query Policy
aws lambda get-function-url-config --function-name my-fn --query AuthType

# Auto Scaling: capacity matches intent
aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names my-asg \
  --query 'AutoScalingGroups[0].[MinSize,DesiredCapacity,MaxSize]'

# Beanstalk: environment healthy on the expected version
aws elasticbeanstalk describe-environments --environment-names my-env \
  --query 'Environments[0].{Health:Health,Status:Status,Version:VersionLabel,CNAME:CNAME}'

# Lightsail firewall state after port changes
aws lightsail get-instance-port-states --instance-name my-instance

# Deletion proof: expect an empty result or NotFound error
aws ec2 describe-volumes --volume-ids vol-012345 2>&1 | grep -q InvalidVolume.NotFound
aws lambda get-function --function-name my-fn 2>&1 | grep -q ResourceNotFoundException
```

After any permission or policy mutation (`add-permission`, `put-application-policy`, `modify-vpc-endpoint-service-permissions`, image or snapshot attributes), read the policy back and diff it against intent before closing the change.
