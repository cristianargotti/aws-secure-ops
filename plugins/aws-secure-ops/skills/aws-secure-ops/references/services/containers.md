# Containers: secure operation patterns

Scope: ECR (private registry), ECR Public, ECS (clusters, services, tasks), EKS (clusters, nodegroups, addons, access management), EKS Auth (pod identity credential exchange).

## Services covered

- `ecr`: private container registry, image storage, lifecycle policies, replication, scanning, registry and repository resource policies.
- `ecs`: container orchestration, clusters, services, task definitions, capacity providers, deployments.
- `eks`: managed Kubernetes control planes, nodegroups, Fargate profiles, addons, access entries, pod identity associations.
- Long tail: `ecr-public` (public gallery repositories, same shape as ecr with public exposure by default), `eks-auth` (single operation, `assume-role-for-pod-identity`, emits credentials, workload internal).

## Querying safely

All list operations in this domain paginate. Always bound them with `--max-items` or server-side filters; never dump a whole registry or cluster.

ECR, target one repository at a time:

```bash
aws ecr describe-repositories --repository-names my-repo \
  --query 'repositories[].{name:repositoryName,uri:repositoryUri,mutability:imageTagMutability}'

aws ecr describe-images --repository-name my-repo \
  --image-ids imageTag=v1.2.3 \
  --query 'imageDetails[].{digest:imageDigest,pushed:imagePushedAt,size:imageSizeInBytes}'

# Newest images only, bounded
aws ecr describe-images --repository-name my-repo --max-items 20 \
  --query 'sort_by(imageDetails,&imagePushedAt)[-10:].[imageTags[0],imageDigest]'

# Untagged candidates for cleanup, server-side filter
aws ecr list-images --repository-name my-repo \
  --filter tagStatus=UNTAGGED --max-items 100

aws ecr get-repository-policy --repository-name my-repo
aws ecr get-registry-policy
aws ecr describe-image-scan-findings --repository-name my-repo \
  --image-id imageTag=v1.2.3 \
  --query '{status:imageScanStatus.status,counts:imageScanFindings.findingSeverityCounts}'
```

ECS, describe calls accept explicit ARN lists, so list first with bounds, then describe named targets:

```bash
aws ecs list-clusters --max-items 50
aws ecs describe-clusters --clusters my-cluster \
  --query 'clusters[].{name:clusterName,status:status,running:runningTasksCount,pending:pendingTasksCount}'

aws ecs list-services --cluster my-cluster --max-items 50
aws ecs describe-services --cluster my-cluster --services my-service \
  --query 'services[].{status:status,desired:desiredCount,running:runningCount,deployments:deployments[].{id:id,status:status,rollout:rolloutState}}'

# Filter tasks server-side by service, status, or family
aws ecs list-tasks --cluster my-cluster --service-name my-service --desired-status RUNNING
aws ecs describe-tasks --cluster my-cluster --tasks TASK_ARN \
  --query 'tasks[].{last:lastStatus,health:healthStatus,stopped:stoppedReason}'

# Task definitions: latest ACTIVE revision only, never the full history
aws ecs list-task-definitions --family-prefix my-family --status ACTIVE --sort DESC --max-items 5
aws ecs describe-task-definition --task-definition my-family \
  --query 'taskDefinition.{rev:revision,cpu:cpu,mem:memory,images:containerDefinitions[].image}'
```

EKS:

```bash
aws eks list-clusters --max-items 20
aws eks describe-cluster --name my-cluster \
  --query 'cluster.{status:status,version:version,endpointAccess:resourcesVpcConfig.{public:endpointPublicAccess,private:endpointPrivateAccess,cidrs:publicAccessCidrs}}'

aws eks list-nodegroups --cluster-name my-cluster
aws eks describe-nodegroup --cluster-name my-cluster --nodegroup-name my-ng \
  --query 'nodegroup.{status:status,version:version,scaling:scalingConfig,health:health.issues}'

aws eks list-addons --cluster-name my-cluster
aws eks list-access-entries --cluster-name my-cluster --max-items 50
aws eks list-associated-access-policies --cluster-name my-cluster --principal-arn PRINCIPAL_ARN
aws eks list-pod-identity-associations --cluster-name my-cluster --namespace my-ns
```

Credential-emitting reads (treat output as a secret, never log or paste it):

- `aws ecr get-login-password`, `aws ecr get-authorization-token`: registry credentials valid 12 hours. Pipe directly into `docker login --password-stdin`; never write to a file or shell history.
- `aws eks get-token`: bearer token for the Kubernetes API. Prefer `aws eks update-kubeconfig --name my-cluster` which stores an exec plugin reference, not a static token.
- `aws ecr get-download-url-for-layer`: returns a pre-signed URL, a bearer capability for the layer blob. Proxy internal use; avoid interactively.

## Mutating safely

No operation in this domain supports `--dry-run` and there is no changeset mechanism. Compensate with: read-back of current state before the change, one target per command, tags at creation time, and staged rollouts where the service offers them.

Tag at creation (all three major services accept `--tags` on create):

```bash
aws ecr create-repository --repository-name my-repo \
  --image-tag-mutability IMMUTABLE \
  --image-scanning-configuration scanOnPush=true \
  --tags Key=project,Value=myproj Key=owner,Value=team

aws ecs create-service --cluster my-cluster --service-name my-service \
  --task-definition my-family:12 --desired-count 2 \
  --deployment-configuration 'deploymentCircuitBreaker={enable=true,rollback=true},maximumPercent=200,minimumHealthyPercent=100' \
  --tags key=project,value=myproj    # note: ECS tag syntax is lowercase key=/value=

aws eks create-nodegroup --cluster-name my-cluster --nodegroup-name my-ng \
  --scaling-config minSize=1,maxSize=3,desiredSize=2 \
  --update-config maxUnavailable=1 \
  --node-role NODE_ROLE_ARN --subnets subnet-a subnet-b \
  --tags project=myproj
```

Staged flows that substitute for changesets:

- ECR lifecycle policy: always run `start-lifecycle-policy-preview` and read `get-lifecycle-policy-preview` (waiter available) before `put-lifecycle-policy`. The preview lists exactly which images the rules would expire. A wrong rule mass-deletes images silently on a schedule.
- ECS deployments: `register-task-definition` creates a new immutable revision (safe, additive), then `update-service --task-definition family:NN` starts a rolling deployment. Enable the deployment circuit breaker with rollback so a bad revision self-reverts. Verify with `describe-services` deployments and `rolloutState`.
- ECS blue/green: `create-task-set` plus `update-service-primary-task-set` shifts traffic explicitly, keeping the old set for rollback.
- EKS upgrades: upgrade the control plane first (`update-cluster-version`, one minor version at a time), wait for `cluster-active`, then nodegroups (`update-nodegroup-version`), then addons (`update-addon`). Every update returns an update id; poll it with `describe-update --update-id`.

Trust and exposure boundary mutations, review the policy document before applying and require confirmation:

- `ecr set-repository-policy`, `ecr put-registry-policy`: repository or registry resource policies can grant cross-account or public pull/push. Read the current policy first, apply the JSON from a reviewed file, read back.
- `ecr put-replication-configuration`: can replicate images to other accounts, an implicit data-sharing grant.
- `eks create-access-entry`, `associate-access-policy`, `update-access-entry`: grant IAM principals Kubernetes access. Scope the policy (`--access-scope type=namespace,namespaces=my-ns`) rather than cluster-wide admin.
- `eks create-pod-identity-association`, `update-pod-identity-association`: bind an IAM role to a service account; every pod under that account gets the role.

One target per command: `batch-delete-image` and `delete-task-definitions` accept lists; pass exactly one image id or one revision per invocation so the audit trail maps one command to one resource.

## Destructive traps

| Command                                                  | Why dangerous                                                                                                                                             | Safe procedure                                                                                                                                      |
| -------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ecr delete-repository --force`                          | Deletes the repository and every image in it, irreversibly                                                                                                | Never use `--force`. List images, delete explicitly, then delete the empty repository                                                               |
| `ecr batch-delete-image`                                 | Deleting by tag on a multi-tag image deletes the whole image (all tags); running services keep working but can no longer scale or restart from that image | Delete by digest, one image per call, after confirming no service or task definition references it                                                  |
| `ecr put-lifecycle-policy`                               | Rules run automatically and mass-expire images with no confirmation                                                                                       | Preview first (`start-lifecycle-policy-preview` + waiter), inspect the expiring set, then apply                                                     |
| `ecr set-repository-policy` / `put-registry-policy`      | Can silently make images pullable cross-account or publicly                                                                                               | Diff against `get-repository-policy` output, apply from reviewed file, read back                                                                    |
| `ecr update-image-storage-class` (to archive)            | Archived images cannot be pulled until restored; scale-out and node replacement fail for services still referencing them                                  | Confirm no active task definition references the image before archiving                                                                             |
| `ecs delete-service --force`                             | Deletes a service that still has running tasks, killing them                                                                                              | Scale to zero first (`update-service --desired-count 0`), wait `services-stable`, then delete without `--force`                                     |
| `ecs update-service --desired-count 0`                   | Stops every task of a live service, a full outage in one flag                                                                                             | Confirm the service and cluster explicitly; prefer scaling down gradually and watching `runningCount`                                               |
| `ecs stop-task`                                          | Terminates a running workload immediately (SIGTERM then SIGKILL after the stop timeout)                                                                   | Confirm the task ARN belongs to the intended service; always pass `--reason` for the audit trail                                                    |
| `ecs delete-cluster`                                     | Fails on active resources, so operators reach for force-deleting the contents first                                                                       | Drain and delete services and instances deliberately; the cluster delete itself should be the trivial last step                                     |
| `ecs deregister-container-instance --force`              | Orphans tasks still running on the instance                                                                                                               | Set the instance to DRAINING (`update-container-instances-state`), wait for tasks to relocate, then deregister without force                        |
| `eks delete-cluster`                                     | Destroys the control plane; nodegroups and Fargate profiles must go first, and workload state in etcd is gone                                             | Delete nodegroups and profiles, wait for their `-deleted` waiters, snapshot any needed Kubernetes manifests, then delete and wait `cluster-deleted` |
| `eks delete-nodegroup`                                   | Terminates every node in the group; pods are evicted                                                                                                      | Confirm workloads reschedule elsewhere or accept the outage; wait `nodegroup-deleted`                                                               |
| `eks delete-access-entry` / `disassociate-access-policy` | Revokes a principal's cluster access; can lock out the last admin                                                                                         | Verify at least one other admin access entry exists before removing                                                                                 |
| `eks update-cluster-config` (endpoint access)            | Disabling public endpoint access or narrowing `publicAccessCidrs` can cut off operator and CI access instantly                                            | Verify private access path works first; change one dimension at a time and confirm reachability                                                     |

## Waiters and timing

| Service | Waiter                            | Delay x attempts | Max wait | Polls                        |
| ------- | --------------------------------- | ---------------- | -------- | ---------------------------- |
| ecr     | image-scan-complete               | 5s x 60          | 5 min    | describe-image-scan-findings |
| ecr     | lifecycle-policy-preview-complete | 5s x 20          | 100 s    | get-lifecycle-policy-preview |
| ecs     | services-stable                   | 15s x 40         | 10 min   | describe-services            |
| ecs     | services-inactive                 | 15s x 40         | 10 min   | describe-services            |
| ecs     | tasks-running                     | 6s x 100         | 10 min   | describe-tasks               |
| ecs     | tasks-stopped                     | 6s x 100         | 10 min   | describe-tasks               |
| eks     | cluster-active / cluster-deleted  | 30s x 40         | 20 min   | describe-cluster             |
| eks     | nodegroup-active                  | 30s x 80         | 40 min   | describe-nodegroup           |
| eks     | nodegroup-deleted                 | 30s x 40         | 20 min   | describe-nodegroup           |
| eks     | addon-active / addon-deleted      | 10s x 60         | 10 min   | describe-addon               |
| eks     | fargate-profile-active            | 10s x 60         | 10 min   | describe-fargate-profile     |
| eks     | fargate-profile-deleted           | 30s x 60         | 30 min   | describe-fargate-profile     |

```bash
aws ecs wait services-stable --cluster my-cluster --services my-service
aws eks wait nodegroup-active --cluster-name my-cluster --nodegroup-name my-ng
```

Where no waiter exists, poll a bounded read, never an open loop:

- EKS control-plane or config updates: `aws eks describe-update --name my-cluster --update-id ID --query 'update.status'` every 30 s, cap at 40 attempts. EKS cluster creation and version upgrades routinely take 10 to 25 minutes; do not shorten the cap.
- ECS service deployment detail: `describe-services --query 'services[0].deployments[?status==`PRIMARY`].rolloutState'` every 15 s, cap at 40; `COMPLETED` or `FAILED` terminates the loop.
- ECR replication of a specific image: `describe-image-replication-status --repository-name my-repo --image-id imageDigest=DIGEST` every 15 s, cap at 20.
- Note the 10 minute ceiling on `services-stable`: services with slow health checks or large task counts can exceed it. On timeout, inspect `events` and `rolloutState` before retrying the waiter once; never loop the waiter unbounded.

## Verification after change

Prove every mutation with a read-back of the specific target:

```bash
# Image pushed or deleted
aws ecr describe-images --repository-name my-repo --image-ids imageTag=v1.2.3   # exists
aws ecr list-images --repository-name my-repo --filter tagStatus=UNTAGGED       # cleanup landed

# Policy applied exactly as intended
aws ecr get-repository-policy --repository-name my-repo --query policyText
aws ecr get-lifecycle-policy --repository-name my-repo --query lifecyclePolicyText

# ECS deployment converged on the intended revision
aws ecs describe-services --cluster my-cluster --services my-service \
  --query 'services[0].{taskDef:taskDefinition,desired:desiredCount,running:runningCount,rollout:deployments[0].rolloutState,events:events[:3].message}'

# Task stopped and why
aws ecs describe-tasks --cluster my-cluster --tasks TASK_ARN \
  --query 'tasks[0].{last:lastStatus,code:stopCode,reason:stoppedReason}'

# EKS update finished successfully (not just cluster ACTIVE)
aws eks describe-update --name my-cluster --update-id ID \
  --query 'update.{status:status,errors:errors}'
aws eks describe-cluster --name my-cluster --query 'cluster.{status:status,version:version}'

# Access grant landed with the intended scope
aws eks list-associated-access-policies --cluster-name my-cluster \
  --principal-arn PRINCIPAL_ARN
aws eks describe-pod-identity-association --cluster-name my-cluster --association-id ID \
  --query 'association.{role:roleArn,sa:serviceAccount,ns:namespace}'

# Nodegroup change healthy, not merely present
aws eks describe-nodegroup --cluster-name my-cluster --nodegroup-name my-ng \
  --query 'nodegroup.{status:status,issues:health.issues}'
```

For deletions, verify absence: the describe call must return `RepositoryNotFoundException`, `ResourceNotFoundException`, or an empty result, and for ECS services the status must read `INACTIVE`, not merely `DRAINING`.
