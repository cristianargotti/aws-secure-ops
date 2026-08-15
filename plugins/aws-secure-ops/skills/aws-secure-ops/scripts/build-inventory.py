#!/usr/bin/env python3
"""Build a complete, machine-readable operation inventory from the AWS CLI's
embedded botocore service models.

The inventory is the empirical backbone of the aws-secure-ops skill: every
operation exposed by the installed CLI is listed with a risk class, so that
tooling (and reviewers) can decide how an operation must be handled before it
runs. Nothing here calls AWS; the only input is the model data shipped inside
the CLI installation.

Outputs (written to --out-dir):
  inventory.csv  service,operation,class,sensitive,dryrun,paginated,source
  waiters.csv    service,waiter,delay_seconds,max_attempts,polled_operation
  summary.json   totals per class, per service, coverage counters
  domains.json   domain -> [services] partition used for human review

Classes:
  read     no state change, no credential material
  execute  side effect without infrastructure CRUD (invoke, send, start job)
  create   provisions a new resource
  modify   changes an existing resource or its configuration
  destroy  removes, terminates, or disrupts a resource
Sensitive flag (independent of class): the operation emits credential/secret
material, changes a trust or exposure boundary, commits spend, or disrupts a
running workload. Sensitive operations warrant explicit human confirmation.

Unknown verbs default to modify + sensitive: an operation is treated as a
guarded mutation until a human review proves otherwise.
"""

import argparse
import csv
import gzip
import json
import re
import shutil
import sys
from pathlib import Path

# --------------------------------------------------------------------------
# Model location
# --------------------------------------------------------------------------


def find_data_dir(explicit):
    if explicit:
        p = Path(explicit)
        if not p.is_dir():
            sys.exit(f"data dir not found: {p}")
        return p
    aws = shutil.which("aws")
    if not aws:
        sys.exit("aws binary not found on PATH; pass --data-dir")
    root = Path(aws).resolve()
    for base in [root.parent.parent, *root.parents]:
        hits = list(base.glob("**/botocore/data"))
        if hits:
            return hits[0]
    sys.exit("could not locate botocore/data next to the aws binary; pass --data-dir")


def load_model(path):
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            return json.load(fh)
    return json.loads(path.read_text(encoding="utf-8"))


def model_file(version_dir, stem):
    for name in (f"{stem}.json", f"{stem}.json.gz"):
        p = version_dir / name
        if p.exists():
            return p
    return None


# --------------------------------------------------------------------------
# Naming
# --------------------------------------------------------------------------

# Model directory name -> CLI command name, where they differ.
CLI_NAME = {
    "s3": "s3api",
    "elasticloadbalancing": "elb",
    "elasticloadbalancingv2": "elbv2",
    "config": "configservice",
}

_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def kebab(op):
    return _CAMEL.sub("-", op).lower()


# --------------------------------------------------------------------------
# Classification rules (first pass; refined by domain review)
# --------------------------------------------------------------------------

# Operations that emit credential or secret material, or mint identity.
SECRET_OPS = {
    "GetSecretValue",
    "GetAuthorizationToken",
    "GetSessionToken",
    "GetFederationToken",
    "AssumeRole",
    "AssumeRoleWithSAML",
    "AssumeRoleWithWebIdentity",
    "AssumeRoot",
    "GetPasswordData",
    "GenerateDataKey",
    "GenerateDataKeyPair",
    "Decrypt",
    "GetClusterCredentials",
    "GetClusterCredentialsWithIAM",
    "GetCredentialsForIdentity",
    "GetOpenIdToken",
    "GetOpenIdTokenForDeveloperIdentity",
    "CreateAccessKey",
    "CreateLoginProfile",
    "CreateServiceSpecificCredential",
    "ResetServiceSpecificCredential",
    "GetRoleCredentials",
    "GetDbConnectAdminAuthToken",
    "GetDbConnectAuthToken",
}

# Parameter reads that can return decrypted values; class stays read but the
# sensitive flag forces a confirmation so plaintext never lands in transcripts
# by accident.
SENSITIVE_READS = {
    "GetParameter",
    "GetParameters",
    "GetParametersByPath",
    "GetParameterHistory",
    "BatchGetSecretValue",
}

# Exact-name overrides: OpName -> (class, sensitive). Applied before prefix
# rules. Keep this list curated and boring; domain review extends it.
EXACT = {
    # EC2 lifecycle
    "RunInstances": ("create", 0),
    "StartInstances": ("modify", 0),
    "StopInstances": ("destroy", 1),
    "RebootInstances": ("destroy", 1),
    "TerminateInstances": ("destroy", 1),
    # Disruptive database lifecycle
    "StopDBInstance": ("destroy", 1),
    "StopDBCluster": ("destroy", 1),
    "RebootDBInstance": ("destroy", 1),
    "RebootDBCluster": ("destroy", 1),
    "FailoverDBCluster": ("destroy", 1),
    "FailoverGlobalCluster": ("destroy", 1),
    # Audit/telemetry kill switches: disabling visibility is a destroy-tier act
    "StopLogging": ("destroy", 1),
    "DeleteTrail": ("destroy", 1),
    "StopConfigurationRecorder": ("destroy", 1),
    "DeleteConfigurationRecorder": ("destroy", 1),
    "DisableSecurityHub": ("destroy", 1),
    "DisableMacie": ("destroy", 1),
    "DeleteDetector": ("destroy", 1),
    "DisableKey": ("destroy", 1),
    "ScheduleKeyDeletion": ("destroy", 1),
    "CancelKeyDeletion": ("modify", 0),
    "DeleteFlowLogs": ("destroy", 1),
    "DisableEbsEncryptionByDefault": ("modify", 1),
    # Account/organization blast radius
    "LeaveOrganization": ("destroy", 1),
    "RemoveAccountFromOrganization": ("destroy", 1),
    "CloseAccount": ("destroy", 1),
    # Exposure boundaries
    "PutBucketPolicy": ("modify", 1),
    "DeleteBucketPolicy": ("destroy", 1),
    "PutBucketAcl": ("modify", 1),
    "PutObjectAcl": ("modify", 1),
    "PutPublicAccessBlock": ("modify", 1),
    "DeletePublicAccessBlock": ("destroy", 1),
    "ModifyImageAttribute": ("modify", 1),
    "ModifySnapshotAttribute": ("modify", 1),
    "ModifyDBSnapshotAttribute": ("modify", 1),
    "ModifyDBClusterSnapshotAttribute": ("modify", 1),
    "ModifyInstanceAttribute": ("modify", 1),
    "AuthorizeSecurityGroupIngress": ("modify", 1),
    "AuthorizeSecurityGroupEgress": ("modify", 1),
    "PutRegistryPolicy": ("modify", 1),
    "SetRepositoryPolicy": ("modify", 1),
    "PutResourcePolicy": ("modify", 1),
    "DeleteResourcePolicy": ("destroy", 1),
    "PutKeyPolicy": ("modify", 1),
    # IAM privilege paths
    "PutUserPolicy": ("modify", 1),
    "PutRolePolicy": ("modify", 1),
    "PutGroupPolicy": ("modify", 1),
    "AttachUserPolicy": ("modify", 1),
    "AttachRolePolicy": ("modify", 1),
    "AttachGroupPolicy": ("modify", 1),
    "CreatePolicyVersion": ("modify", 1),
    "SetDefaultPolicyVersion": ("modify", 1),
    "UpdateAssumeRolePolicy": ("modify", 1),
    "AddUserToGroup": ("modify", 1),
    "UpdateLoginProfile": ("modify", 1),
    "ChangePassword": ("modify", 1),
    "DeactivateMFADevice": ("destroy", 1),
    # Spend commitments
    "PurchaseReservedInstancesOffering": ("create", 1),
    "PurchaseHostReservation": ("create", 1),
    "PurchaseCapacityBlock": ("create", 1),
    "PurchaseReservedDBInstancesOffering": ("create", 1),
    "PurchaseReservedCacheNodesOffering": ("create", 1),
    "PurchaseReservedNodeOffering": ("create", 1),
    "CreateReservedInstancesListing": ("create", 1),
    # Benign job/query stops (default Stop would over-flag)
    "StopQuery": ("execute", 0),
    "StopCrawler": ("execute", 0),
    "StopCrawlerSchedule": ("execute", 0),
    "StopTrigger": ("execute", 0),
    "StopQueryExecution": ("execute", 0),
    "StopTrainingJob": ("execute", 0),
    "StopStreamProcessor": ("execute", 0),
    "StopContinuousExport": ("execute", 0),
    "StopDataCollectionByAgentIds": ("execute", 0),
    # Messaging purge is data destruction
    "PurgeQueue": ("destroy", 1),
    # Read-only simulators and validators
    "SimulatePrincipalPolicy": ("read", 0),
    "SimulateCustomPolicy": ("read", 0),
    "GetCallerIdentity": ("read", 0),
    "GetAccessKeyInfo": ("read", 0),
    "LookupEvents": ("read", 0),
    "TestRenderTemplate": ("read", 0),
    "ValidateTemplate": ("read", 0),
    "EstimateTemplateCost": ("read", 0),
}

# Ordered prefix rules; the first hit wins. Batch* is unwrapped first.
PREFIX_RULES = [
    (
        (
            "Delete",
            "Terminate",
            "Purge",
            "Destroy",
            "Wipe",
            "Remove",
            "Revoke",
            "Deregister",
            "Release",
            "Retire",
            "Forget",
            "Deprecate",
            "Expire",
            "Evict",
            "Uninstall",
            "Unsubscribe",
            "Erase",
            "Untrust",
            "Reboot",
            "Failover",
            "Switchover",
            "Deprovision",
            "Restart",
        ),
        "destroy",
    ),
    (
        (
            "Create",
            "Register",
            "Allocate",
            "Provision",
            "Import",
            "Upload",
            "Clone",
            "Restore",
            "Launch",
            "Duplicate",
            "Renew",
            "Request",
            "Reserve",
            "Subscribe",
            "Snapshot",
            "Mint",
            "Invite",
            "Define",
            "Purchase",
        ),
        "create",
    ),
    (
        (
            "Update",
            "Modify",
            "Put",
            "Set",
            "Reset",
            "Replace",
            "Rotate",
            "Promote",
            "Resize",
            "Rename",
            "Move",
            "Apply",
            "Configure",
            "Assign",
            "Unassign",
            "Merge",
            "Accept",
            "Reject",
            "Approve",
            "Deny",
            "Increase",
            "Decrease",
            "Attach",
            "Detach",
            "Associate",
            "Disassociate",
            "Enable",
            "Disable",
            "Suspend",
            "Resume",
            "Tag",
            "Untag",
            "Cancel",
            "Swap",
            "Transfer",
            "Migrate",
            "Copy",
            "Grant",
            "Authorize",
            "Deauthorize",
            "Override",
            "Archive",
            "Unarchive",
            "Lock",
            "Unlock",
            "Abort",
            "Add",
            "Activate",
            "Deactivate",
            "Upgrade",
            "Change",
            "Dissociate",
            "Write",
            "Initialize",
            "Pause",
            "Disconnect",
            "Rollback",
        ),
        "modify",
    ),
    (
        (
            "Invoke",
            "Send",
            "Publish",
            "Start",
            "Run",
            "Execute",
            "Submit",
            "Trigger",
            "Signal",
            "Notify",
            "Redrive",
            "Retry",
            "Replay",
            "Rerun",
            "Initiate",
            "Complete",
            "Stop",
            "Test",
            "Verify",
            "Export",
            "Generate",
            "Synthesize",
            "Translate",
            "Transcribe",
            "Detect",
            "Classify",
            "Recognize",
            "Predict",
            "Convert",
            "Render",
            "Evaluate",
            "Poll",
            "Claim",
            "Confirm",
            "Refresh",
            "Reindex",
            "Rebuild",
            "Index",
            "Process",
            "Wait",
            "Flush",
            "ReEncrypt",
            "Reencrypt",
            "Sign",
            "Redeem",
            "Exchange",
            "Post",
            "Respond",
            "Resend",
        ),
        "execute",
    ),
    (
        (
            "Get",
            "List",
            "Describe",
            "Head",
            "Lookup",
            "Query",
            "Scan",
            "Select",
            "Search",
            "Check",
            "Validate",
            "Estimate",
            "Preview",
            "Simulate",
            "Discover",
            "Count",
            "Read",
            "Retrieve",
            "View",
            "Resolve",
            "Is",
            "Filter",
            "Download",
            "Fetch",
            "Analyze",
            "Compare",
            "Summarize",
            "Explain",
            "Peek",
            "Calculate",
        ),
        "read",
    ),
]

# Prefixes whose hits are sensitive regardless of class: spend commitments,
# protection toggles, workload disruption, connectivity teardown.
PREFIX_SENS = ("Purchase", "Deactivate", "Pause", "Disconnect", "Rollback")


def classify(op):
    """Return (class, sensitive, rule) for an operation name."""
    if op in SECRET_OPS:
        return "read", 1, "secret"
    if op in SENSITIVE_READS:
        return "read", 1, "sensitive-read"
    if op in EXACT:
        cls, sens = EXACT[op]
        return cls, sens, "exact"
    # Batch*/Admin* wrap another verb; classify the wrapped verb.
    stem = op
    for wrapper in ("Batch", "Admin"):
        if stem.startswith(wrapper) and len(stem) > len(wrapper):
            stem = stem[len(wrapper) :]
    if stem in EXACT:
        cls, sens = EXACT[stem]
        return cls, sens, "exact-wrapped"
    if stem in SECRET_OPS:
        return "read", 1, "secret"
    # Assume* mints credentials for another principal: secret material.
    if stem.startswith("Assume"):
        return "read", 1, "prefix-secret"
    for prefixes, cls in PREFIX_RULES:
        if stem.startswith(prefixes):
            sens = 1 if cls == "destroy" or stem.startswith(PREFIX_SENS) else 0
            return cls, sens, "prefix"
    # Unknown verb: guarded mutation until proven otherwise.
    return "modify", 1, "unknown"


# --------------------------------------------------------------------------
# CLI customizations (commands that do not exist in the service models)
# --------------------------------------------------------------------------

CUSTOM_ROWS = [
    # service, operation, class, sensitive, dryrun, paginated
    ("s3", "ls", "read", 0, 0, 1),
    ("s3", "presign", "read", 1, 0, 0),
    ("s3", "mb", "create", 0, 0, 0),
    ("s3", "cp", "modify", 0, 1, 0),
    ("s3", "mv", "modify", 1, 1, 0),
    ("s3", "sync", "modify", 1, 1, 0),  # --delete makes it destructive
    ("s3", "rm", "destroy", 1, 1, 0),
    ("s3", "rb", "destroy", 1, 0, 0),
    ("s3", "website", "modify", 1, 0, 0),
    ("ecr", "get-login-password", "read", 1, 0, 0),
    ("ecr-public", "get-login-password", "read", 1, 0, 0),
    ("codeartifact", "login", "modify", 1, 0, 0),
    ("eks", "get-token", "read", 1, 0, 0),
    ("eks", "update-kubeconfig", "modify", 0, 0, 0),
    ("rds", "generate-db-auth-token", "read", 1, 0, 0),
    ("ssm", "start-session", "execute", 0, 0, 0),
    ("cloudformation", "deploy", "modify", 0, 0, 0),
    ("cloudformation", "package", "read", 0, 0, 0),
    ("cloudfront", "sign", "read", 1, 0, 0),
    ("configure", "export-credentials", "read", 1, 0, 0),
    ("sso", "login", "read", 0, 0, 0),
    ("sso", "logout", "read", 0, 0, 0),
    ("logs", "tail", "read", 0, 0, 0),  # v2 CLI live log tail: a pure read
]


# --------------------------------------------------------------------------
# Domain partition for human review
# --------------------------------------------------------------------------

DOMAIN_KEYWORDS = {
    "compute": [
        "ec2",
        "autoscaling",
        "lambda",
        "lightsail",
        "batch",
        "imagebuilder",
        "ec2-instance-connect",
        "outposts",
        "serverlessrepo",
        "apprunner",
        "elasticbeanstalk",
    ],
    "storage": [
        "s3",
        "s3api",
        "s3control",
        "s3outposts",
        "s3tables",
        "glacier",
        "efs",
        "fsx",
        "backup",
        "storagegateway",
        "ebs",
        "snowball",
        "snow-device-management",
        "recyclebin",
        "backup-gateway",
        "backupsearch",
    ],
    "identity-security": [
        "iam",
        "sts",
        "sso",
        "sso-admin",
        "sso-oidc",
        "identitystore",
        "organizations",
        "account",
        "secretsmanager",
        "kms",
        "acm",
        "acm-pca",
        "guardduty",
        "securityhub",
        "inspector",
        "inspector2",
        "macie2",
        "waf",
        "wafv2",
        "waf-regional",
        "shield",
        "detective",
        "accessanalyzer",
        "cognito-idp",
        "cognito-identity",
        "cognito-sync",
        "ram",
        "fms",
        "signer",
        "payment-cryptography",
        "payment-cryptography-data",
        "verifiedpermissions",
        "cloudhsm",
        "cloudhsmv2",
        "ds",
        "ds-data",
        "rolesanywhere",
        "pca-connector-ad",
        "pca-connector-scep",
        "security-ir",
    ],
    "networking": [
        "elb",
        "elbv2",
        "route53",
        "route53domains",
        "route53resolver",
        "route53profiles",
        "route53-recovery-cluster",
        "route53-recovery-control-config",
        "route53-recovery-readiness",
        "cloudfront",
        "cloudfront-keyvaluestore",
        "apigateway",
        "apigatewayv2",
        "apigatewaymanagementapi",
        "vpc-lattice",
        "directconnect",
        "globalaccelerator",
        "networkmanager",
        "network-firewall",
        "networkmonitor",
        "networkflowmonitor",
        "servicediscovery",
        "appmesh",
        "arc-zonal-shift",
        "arc-region-switch",
    ],
    "databases": [
        "rds",
        "rds-data",
        "dynamodb",
        "dynamodbstreams",
        "dax",
        "elasticache",
        "redshift",
        "redshift-data",
        "redshift-serverless",
        "neptune",
        "neptune-graph",
        "neptunedata",
        "docdb",
        "docdb-elastic",
        "keyspaces",
        "keyspacesstreams",
        "timestream-query",
        "timestream-write",
        "timestream-influxdb",
        "memorydb",
        "qldb",
        "qldb-session",
        "dsql",
    ],
    "observability": [
        "cloudwatch",
        "logs",
        "cloudtrail",
        "cloudtrail-data",
        "xray",
        "application-insights",
        "applicationcostprofiler",
        "synthetics",
        "rum",
        "evidently",
        "oam",
        "health",
        "service-quotas",
        "servicequotas",
        "ce",
        "cur",
        "bcm-data-exports",
        "bcm-pricing-calculator",
        "bcm-recommended-actions",
        "costoptimizationhub",
        "cost-optimization-hub",
        "budgets",
        "pricing",
        "application-signals",
        "cloudwatch-observability-admin",
        "resource-explorer-2",
        "resourcegroupstaggingapi",
        "resource-groups",
        "support",
        "supportapp",
        "trustedadvisor",
        "compute-optimizer",
        "freetier",
        "invoicing",
    ],
    "messaging-integration": [
        "sns",
        "sqs",
        "events",
        "eventbridge",
        "scheduler",
        "pipes",
        "mq",
        "kafka",
        "kafkaconnect",
        "kinesis",
        "kinesisanalytics",
        "kinesisanalyticsv2",
        "kinesisvideo",
        "kinesis-video-archived-media",
        "kinesis-video-media",
        "kinesis-video-signaling",
        "kinesis-video-webrtc-storage",
        "firehose",
        "ses",
        "sesv2",
        "pinpoint",
        "pinpoint-email",
        "pinpoint-sms-voice",
        "pinpoint-sms-voice-v2",
        "connect",
        "connectcases",
        "connectcampaigns",
        "connectcampaignsv2",
        "connectparticipant",
        "chime",
        "chime-sdk-identity",
        "chime-sdk-media-pipelines",
        "chime-sdk-meetings",
        "chime-sdk-messaging",
        "chime-sdk-voice",
        "stepfunctions",
        "swf",
        "mailmanager",
        "socialmessaging",
        "notifications",
        "notificationscontacts",
        "appfabric",
        "appintegrations",
        "wisdom",
        "qconnect",
    ],
    "deploy-iac": [
        "cloudformation",
        "codebuild",
        "codepipeline",
        "codedeploy",
        "codecommit",
        "codeconnections",
        "codestar-connections",
        "codestar-notifications",
        "codeguru-reviewer",
        "codeguru-security",
        "codeguruprofiler",
        "codecatalyst",
        "ssm",
        "ssm-contacts",
        "ssm-incidents",
        "ssm-sap",
        "ssm-quicksetup",
        "ssm-guiconnect",
        "servicecatalog",
        "servicecatalog-appregistry",
        "appconfig",
        "appconfigdata",
        "amplify",
        "amplifybackend",
        "amplifyuibuilder",
        "proton",
        "launch-wizard",
        "mgn",
        "drs",
        "sms",
        "migrationhub-config",
        "migrationhuborchestrator",
        "migrationhubstrategy",
        "mgh",
        "migration-hub-refactor-spaces",
        "application-autoscaling",
        "resiliencehub",
        "fis",
        "controltower",
        "controlcatalog",
        "auditmanager",
        "license-manager",
        "license-manager-linux-subscriptions",
        "license-manager-user-subscriptions",
        "configservice",
        "cloudcontrol",
        "opsworks",
        "opsworkscm",
    ],
    "containers": ["ecr", "ecr-public", "ecs", "eks", "eks-auth"],
    "data-analytics-ai": [
        "athena",
        "glue",
        "databrew",
        "datazone",
        "lakeformation",
        "emr",
        "emr-containers",
        "emr-serverless",
        "quicksight",
        "sagemaker",
        "sagemaker-a2i-runtime",
        "sagemaker-edge",
        "sagemaker-featurestore-runtime",
        "sagemaker-geospatial",
        "sagemaker-metrics",
        "sagemaker-runtime",
        "bedrock",
        "bedrock-agent",
        "bedrock-agent-runtime",
        "bedrock-agentcore",
        "bedrock-agentcore-control",
        "bedrock-data-automation",
        "bedrock-data-automation-runtime",
        "bedrock-runtime",
        "comprehend",
        "comprehendmedical",
        "rekognition",
        "textract",
        "transcribe",
        "translate",
        "polly",
        "lex-models",
        "lex-runtime",
        "lexv2-models",
        "lexv2-runtime",
        "opensearch",
        "opensearchserverless",
        "es",
        "datasync",
        "dms",
        "appflow",
        "mwaa",
        "dataexchange",
        "datapipeline",
        "forecast",
        "forecastquery",
        "frauddetector",
        "personalize",
        "personalize-events",
        "personalize-runtime",
        "kendra",
        "kendra-ranking",
        "entityresolution",
        "cleanrooms",
        "cleanroomsml",
        "omics",
        "healthlake",
        "medical-imaging",
        "geo-maps",
        "geo-places",
        "geo-routes",
        "location",
        "iotanalytics",
        "qapps",
        "qbusiness",
    ],
}


def build_domains(services):
    assigned = {}
    for domain, names in DOMAIN_KEYWORDS.items():
        for n in names:
            assigned[n] = domain
    domains = {d: [] for d in DOMAIN_KEYWORDS}
    domains["platform-misc"] = []
    for svc in sorted(services):
        domains.setdefault(assigned.get(svc, "platform-misc"), []).append(svc)
    for d in domains.values():
        d.sort()
    return domains


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data-dir", help="botocore data dir (auto-detected if omitted)")
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    data = find_data_dir(args.data_dir)
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    rows = []
    waiter_rows = []
    per_service = {}
    class_totals = {}
    unknown = 0

    service_dirs = sorted(p for p in data.iterdir() if p.is_dir())
    for sdir in service_dirs:
        versions = sorted(p for p in sdir.iterdir() if p.is_dir())
        if not versions:
            continue
        vdir = versions[-1]
        smodel = model_file(vdir, "service-2")
        if not smodel:
            continue
        model = load_model(smodel)
        cli_service = CLI_NAME.get(sdir.name, sdir.name)

        shapes = model.get("shapes", {})
        pag_ops = set()
        pfile = model_file(vdir, "paginators-1")
        if pfile:
            pag_ops = set(load_model(pfile).get("pagination", {}).keys())

        wfile = model_file(vdir, "waiters-2")
        if wfile:
            for wname, wcfg in load_model(wfile).get("waiters", {}).items():
                waiter_rows.append(
                    (
                        cli_service,
                        kebab(wname),
                        wcfg.get("delay", ""),
                        wcfg.get("maxAttempts", ""),
                        kebab(wcfg.get("operation", "")),
                    )
                )

        for op_name, op in sorted(model.get("operations", {}).items()):
            cls, sens, rule = classify(op_name)
            if rule == "unknown":
                unknown += 1
            dryrun = 0
            input_shape = (op.get("input") or {}).get("shape")
            if input_shape and input_shape in shapes:
                members = shapes[input_shape].get("members", {})
                if any(m.lower() == "dryrun" for m in members):
                    dryrun = 1
            rows.append(
                (
                    cli_service,
                    kebab(op_name),
                    cls,
                    sens,
                    dryrun,
                    1 if op_name in pag_ops else 0,
                    "model",
                    rule,
                )
            )
            per_service[cli_service] = per_service.get(cli_service, 0) + 1
            class_totals[cls] = class_totals.get(cls, 0) + 1

    for svc, opn, cls, sens, dry, pag in CUSTOM_ROWS:
        rows.append((svc, opn, cls, sens, dry, pag, "custom", "curated"))
        per_service[svc] = per_service.get(svc, 0) + 1
        class_totals[cls] = class_totals.get(cls, 0) + 1

    rows.sort()
    with (out / "inventory.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(
            [
                "service",
                "operation",
                "class",
                "sensitive",
                "dryrun",
                "paginated",
                "source",
                "rule",
            ]
        )
        w.writerows(rows)

    waiter_rows.sort()
    with (out / "waiters.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(
            ["service", "waiter", "delay_seconds", "max_attempts", "polled_operation"]
        )
        w.writerows(waiter_rows)

    domains = build_domains(sorted(per_service.keys()))
    (out / "domains.json").write_text(json.dumps(domains, indent=2) + "\n")

    summary = {
        "data_dir": str(data),
        "services": len(per_service),
        "operations": len(rows),
        "waiters": len(waiter_rows),
        "class_totals": dict(sorted(class_totals.items())),
        "unknown_verb_operations": unknown,
        "domain_sizes": {d: len(s) for d, s in domains.items()},
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
