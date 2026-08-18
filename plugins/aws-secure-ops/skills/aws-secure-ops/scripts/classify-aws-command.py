#!/usr/bin/env python3
"""Pre-execution gate for aws CLI commands (PreToolUse hook) — hardened build.

Reads the hook event JSON on stdin, classifies every aws invocation in the
command using the same taxonomy as the aws-secure-ops inventory, and emits a
permission decision:

  deny   frozen-profile mutation, loop/batch over a mutating verb, mutating
         command without an inline purpose stamp, tool/automation markers in
         audit-visible values, --no-verify-ssl
  ask    destructive or sensitive operations (human confirmation), secret
         material reads, non-AWS --endpoint-url, untagged creates, mutation
         parameters or policy bodies sourced from files the gate cannot read,
         grants to public principal groups
  allow  everything else (silent exit)

Hardening on top of the base gate (each check only adds strictness; no base
decision is ever loosened):

  1. AWS_PROFILE assignments that persist in the shell (``export FOO=bar`` or
     a bare assignment segment) are tracked across the whole command, so a
     profile exported in an earlier segment still reaches the frozen-profile
     check for later invocations. An implicitly carried profile can only make
     the gate stricter: it never grants the personal-profile exemption, which
     requires an explicit --profile / inline assignment on the invocation.
  2. aws invocations nested inside command substitution ($(...) and
     backticks), process substitution (<(...) / >(...)), and the common inline
     shell wrappers (bash -c / sh -c '<script>', including attached -c'...',
     -o mode -c, and here-strings) are extracted transitively and classified
     like any other invocation. This covers the common forms, not every
     conceivable wrapper -- genuinely novel obfuscation remains a documented
     residual (see references/threat-model.md).
  3. A mutating command that sources its input from --cli-input-json /
     --cli-input-yaml file://... escalates to ask: the gate cannot inspect
     the file, so the operator confirms its contents match the stated intent.
  4. ``find ... -exec ... aws <mutating>`` and ``parallel ... aws
     <mutating>`` join for/while/until and xargs in the loop/batch detector.
  5. Grants to the public principal groups (AllUsers / AuthenticatedUsers,
     via --grant-* flags or the groups/global/... URI) are an exposure
     boundary: marked sensitive and surfaced for confirmation.
  6. A resource/trust policy sourced from a file (--policy,
     --policy-document, --assume-role-policy-document, ... file://...) on a
     mutating call is marked sensitive and surfaced: the gate cannot verify
     the file grants no public or wildcard principal.
  7. Purpose stamps get a second marker pass with separators (- _ .)
     stripped, limited to high-signal brand tokens, so a separator-obfuscated
     tool name cannot slip into the audit trail. Ordinary words that merely
     resemble a brand (e.g. a person's name) do not trip it.

Codex compatibility mode is enabled with ``AWS_OPS_HOOK_RUNTIME=codex`` and
``AWS_OPS_MODE=readonly``. In that mode the gate is deliberately fail-closed:
``ask`` is converted to ``deny`` because Codex does not currently pause on an
``ask`` hook result, the private policy and inventory must be valid, only
explicitly classified read-only profiles may be used, and every non-sensitive
operation must be a bounded read through the trusted AWS CLI path. Execute,
create, modify, destroy, secret/configuration reads, custom endpoints, implicit
profiles/regions, and unbounded paginated reads are denied.

Outside Codex compatibility mode the upstream Claude behavior is retained,
including its documented fail-open policy fallback. Account names stay in the
private policy file; they are never hardcoded in this shareable gate.

Local decision ledger: the gate appends one JSON line per inspected aws
invocation (allow, ask, and deny alike) to AWS_OPS_LEDGER_FILE if set, else
~/.claude/aws-ops-ledger.jsonl. Disabled when the policy file has
"ledger": false. Only classification metadata is written — never raw command
text, argument values, tag values, or secret material. Ledger I/O is
best-effort: a failure never raises, delays, or changes the gate decision.

Configuration (optional for Claude; required and fail-closed for Codex):
  ~/.claude/aws-ops.policy.json     override path: AWS_OPS_POLICY_FILE
  {
    "operator": {"name": "...", "stamp_prefix": "xx"},
    "profiles": {"prof-name": "readonly|admin|frozen|personal", ...},
    "required_tags": {"key": "value", ...},
    "ledger": true
  }

The gate is a seatbelt, not the judgment. The Claude lane retains the legacy
parse fallback described in the threat model. The Codex lane first discovers a
real executable candidate, ignores plain AWS text, and then fails closed on
malformed/indirect candidates or operations it cannot classify.
"""

import csv
import fnmatch
import json
import os
import re
import stat
import sys
import unicodedata
from datetime import datetime, timezone
from pathlib import Path


def default_trusted_aws_cli():
    """Choose a known absolute AWS CLI path without consulting PATH."""
    candidates = (
        "/opt/homebrew/bin/aws",
        "/usr/local/bin/aws",
        "/usr/bin/aws",
    )
    for candidate in candidates:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return candidates[0]


STAMP_VAR = "AWS_SDK_UA_APP_ID"
MAX_STAMP_LEN = 50

# Codex's current hook runtime parses ``ask`` but does not pause execution for
# approval. Keep the upstream classifier intact for Claude, and activate this
# stricter local lane only when the Codex hook sets both variables.
CODEX_RUNTIME = os.environ.get("AWS_OPS_HOOK_RUNTIME") == "codex"
CODEX_READ_ONLY = CODEX_RUNTIME and os.environ.get("AWS_OPS_MODE") == "readonly"
TRUSTED_AWS_CLI = os.environ.get("AWS_OPS_TRUSTED_AWS_CLI", default_trusted_aws_cli())
MAX_CODEX_PAGE_ITEMS = 100
MAX_CODEX_TIMEOUT_SECONDS = 120
MAX_CODEX_COMMAND_CHARS = 131_072
MAX_CODEX_SUBSTITUTION_MARKERS = 64
MAX_CODEX_SEGMENT_MARKERS = 256
MAX_CODEX_SHELL_WRAPPERS = 32
MAX_POLICY_BYTES = 1_048_576
MAX_INVENTORY_BYTES = 16_777_216
MAX_AWS_ALIAS_BYTES = 262_144
INVENTORY_PATH = (
    Path(__file__).resolve().parent.parent
    / "references"
    / "inventory"
    / "inventory.csv"
)
CODEX_STAMP = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
SHELL_ASSIGNMENT = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=(.*)\Z", re.DOTALL)
CODEX_ALLOWED_PREFIX_ASSIGNMENTS = {
    STAMP_VAR,
    "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS",
}
AWS_GLOBAL_FLAGS = frozenset(
    {
        "--debug",
        "--endpoint-url",
        "--no-verify-ssl",
        "--no-paginate",
        "--output",
        "--query",
        "--profile",
        "--region",
        "--version",
        "--color",
        "--no-sign-request",
        "--ca-bundle",
        "--cli-read-timeout",
        "--cli-connect-timeout",
        "--cli-binary-format",
        "--cli-error-format",
        "--no-cli-pager",
        "--cli-auto-prompt",
        "--no-cli-auto-prompt",
    }
)
CODEX_FORBIDDEN_GLOBAL_FLAGS = (
    "--debug",
    "--endpoint-url",
    "--ca-bundle",
    "--no-verify-ssl",
    "--cli-auto-prompt",
)
CODEX_EXACT_ONLY_FLAGS = frozenset(
    {
        *CODEX_FORBIDDEN_GLOBAL_FLAGS,
        "--profile",
        "--region",
        "--max-items",
        "--page-size",
        "--no-cli-pager",
        "--no-cli-auto-prompt",
        "--cli-read-timeout",
        "--cli-connect-timeout",
    }
)
CODEX_EXECUTION_WRAPPERS = {
    "!",
    "(",
    "{",
    "alias",
    "arch",
    "ash",
    "bash",
    "builtin",
    "busybox",
    "caffeinate",
    "case",
    "chroot",
    "chpst",
    "command",
    "coproc",
    "cp",
    "do",
    "doas",
    "dash",
    "daemonize",
    "elif",
    "else",
    "env",
    "eval",
    "expect",
    "exec",
    "find",
    "fish",
    "flock",
    "for",
    "function",
    "hash",
    "if",
    "install",
    "ionice",
    "ln",
    "ksh",
    "mv",
    "nice",
    "nocorrect",
    "noglob",
    "nohup",
    "nsenter",
    "parallel",
    "perf",
    "prlimit",
    "rlwrap",
    "runuser",
    "script",
    "screen",
    "select",
    "setpriv",
    "setsid",
    "setuidgid",
    "sh",
    "su",
    "sudo",
    "stdbuf",
    "start-stop-daemon",
    "strace",
    "systemd-run",
    "taskset",
    "then",
    "time",
    "timeout",
    "tmux",
    "toybox",
    "unshare",
    "until",
    "valgrind",
    "watch",
    "while",
    "xargs",
    "zsh",
}
CODEX_BODY_EXECUTION_WRAPPERS = frozenset(
    {
        "ash",
        "bash",
        "dash",
        "doas",
        "eval",
        "expect",
        "fish",
        "ksh",
        "runuser",
        "screen",
        "sh",
        "su",
        "sudo",
        "systemd-run",
        "tmux",
        "zsh",
    }
)
CODEX_TEXT_ARGUMENT_COMMANDS = frozenset(
    {"awk", "cat", "echo", "grep", "printf", "rg", "sed"}
)
CODEX_EXECUTABLE_PREPARATION = frozenset(
    {"alias", "cat", "cp", "dd", "hash", "install", "ln", "mv"}
)
CODEX_PIPELINE_EXECUTORS = {
    "ash",
    "bash",
    "dash",
    "eval",
    "ksh",
    "parallel",
    "sh",
    "xargs",
    "zsh",
}
CODEX_CONTEXT_ENV = (
    "HOME",
    "PATH",
    "BASH_ENV",
    "ENV",
    "ZDOTDIR",
    "PYTHONHOME",
    "PYTHONPATH",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "BOTO_CONFIG",
    "AWS_DATA_PATH",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "SSLKEYLOGFILE",
    "https_proxy",
    "http_proxy",
    "all_proxy",
    "no_proxy",
)
CODEX_POLICY_ALLOWLIST_ENV = frozenset(
    {
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "https_proxy",
        "http_proxy",
        "all_proxy",
        "no_proxy",
    }
)

# These inherited variables can silently override the named profile, region,
# TLS trust, credential source, or endpoint. Codex read-only sessions must be
# launched clean instead of trying to reason about their precedence.
UNSAFE_INHERITED_AWS_ENV = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
    "AWS_ROLE_ARN",
    "AWS_ROLE_SESSION_NAME",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "AWS_ENDPOINT_URL",
    "AWS_CONFIG_FILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_CA_BUNDLE",
)
UNSAFE_INHERITED_RUNTIME_ENV = (
    "BASH_ENV",
    "ENV",
    "ZDOTDIR",
    "PYTHONHOME",
    "PYTHONPATH",
    "PYTHONINSPECT",
    "PYTHONSTARTUP",
    "PYTHONWARNINGS",
    "PYTHONBREAKPOINT",
    "PYTHONUSERBASE",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "BOTO_CONFIG",
    "AWS_DATA_PATH",
    "SSLKEYLOGFILE",
)
CODEX_INTERNAL_AWS_ENV = frozenset(
    {
        "AWS_OPS_HOOK_RUNTIME",
        "AWS_OPS_MODE",
        "AWS_OPS_POLICY_FILE",
        "AWS_OPS_LEDGER_FILE",
        "AWS_OPS_UNSAFE_LAUNCH_ENV",
        "AWS_OPS_TRUSTED_AWS_CLI",
    }
)

# Flags whose value is the next token (skipped when locating service/operation).
VALUE_FLAGS = {
    "--profile",
    "--region",
    "--output",
    "--endpoint-url",
    "--query",
    "--color",
    "--ca-bundle",
    "--cli-connect-timeout",
    "--cli-read-timeout",
    "--cli-binary-format",
    "--cli-error-format",
    "--sts-regional-endpoints",
}

# Verb -> class fallback, aligned with references/operation-classes.md.
VERB_CLASS = {}
for _verbs, _cls in (
    (
        (
            "delete",
            "terminate",
            "purge",
            "destroy",
            "wipe",
            "remove",
            "revoke",
            "deregister",
            "release",
            "retire",
            "forget",
            "deprecate",
            "expire",
            "evict",
            "uninstall",
            "unsubscribe",
            "erase",
            "reboot",
            "failover",
            "switchover",
            "deprovision",
            "restart",
            "rm",
            "rb",
        ),
        "destroy",
    ),
    (
        (
            "create",
            "register",
            "allocate",
            "provision",
            "import",
            "upload",
            "clone",
            "restore",
            "launch",
            "duplicate",
            "renew",
            "request",
            "reserve",
            "subscribe",
            "invite",
            "define",
            "purchase",
            "mb",
        ),
        "create",
    ),
    (
        (
            "update",
            "modify",
            "put",
            "set",
            "reset",
            "replace",
            "rotate",
            "promote",
            "resize",
            "rename",
            "move",
            "apply",
            "configure",
            "assign",
            "unassign",
            "merge",
            "accept",
            "reject",
            "approve",
            "deny",
            "increase",
            "decrease",
            "attach",
            "detach",
            "associate",
            "disassociate",
            "enable",
            "disable",
            "suspend",
            "resume",
            "tag",
            "untag",
            "cancel",
            "swap",
            "transfer",
            "migrate",
            "copy",
            "grant",
            "authorize",
            "deauthorize",
            "override",
            "archive",
            "unarchive",
            "lock",
            "unlock",
            "abort",
            "add",
            "activate",
            "deactivate",
            "upgrade",
            "change",
            "dissociate",
            "write",
            "initialize",
            "pause",
            "disconnect",
            "rollback",
            "cp",
            "mv",
            "sync",
        ),
        "modify",
    ),
    (
        (
            "invoke",
            "send",
            "publish",
            "start",
            "run",
            "execute",
            "submit",
            "trigger",
            "signal",
            "notify",
            "redrive",
            "retry",
            "replay",
            "rerun",
            "initiate",
            "complete",
            "stop",
            "test",
            "verify",
            "export",
            "generate",
            "synthesize",
            "translate",
            "transcribe",
            "detect",
            "classify",
            "recognize",
            "predict",
            "convert",
            "render",
            "evaluate",
            "poll",
            "claim",
            "confirm",
            "refresh",
            "reindex",
            "rebuild",
            "index",
            "process",
            "flush",
            "sign",
            "redeem",
            "exchange",
            "post",
            "respond",
            "resend",
        ),
        "execute",
    ),
    (
        (
            "get",
            "list",
            "describe",
            "head",
            "lookup",
            "query",
            "scan",
            "select",
            "search",
            "check",
            "validate",
            "estimate",
            "preview",
            "simulate",
            "discover",
            "count",
            "read",
            "retrieve",
            "view",
            "resolve",
            "is",
            "filter",
            "download",
            "fetch",
            "analyze",
            "compare",
            "summarize",
            "explain",
            "peek",
            "calculate",
            "ls",
            "wait",
            "help",
            "presign",
        ),
        "read",
    ),
):
    for _v in _verbs:
        VERB_CLASS[_v] = _cls

# Tool/automation markers banned from audit-visible values (stamps, tags).
# Deliberately narrow: attribution rules ban tool names, not ordinary words.
MARKERS = re.compile(
    r"(?<![a-z0-9])(claude|anthropic|copilot|openai|chatgpt|gemini|llm|"
    r"ai-generated|ai-assisted|generated-by|assistant|autonomous-agent)"
    r"(?![a-z0-9])",
    re.IGNORECASE,
)

# High-signal brand tokens for the separator-stripped second pass over purpose
# stamps. Kept short and unambiguous on purpose: with separators removed, a
# broad list would start matching ordinary words. Names that merely resemble a
# brand (e.g. "claudia") do not contain these substrings once stripped.
BRAND_TOKENS = ("claude", "anthropic", "openai", "chatgpt", "copilot", "gemini")

# Public principal groups: a grant to either is a world-exposure boundary.
PUBLIC_GRANT = re.compile(
    r"global/(?:AllUsers|AuthenticatedUsers)\b"
    r"|--grant[a-z-]*[=\s][^;|&]*\b(?:AllUsers|AuthenticatedUsers)\b"
)

# A resource/trust policy body sourced from a file the gate cannot read.
# Matches --policy, --policy-document, --assume-role-policy-document, ... but
# not value-bearing cousins like --policy-arn or --policy-name.
POLICY_FILE = re.compile(r"--(?:[a-z]+-)*policy(?:-document)?[=\s]\s*[\"']?file://")

# Skeleton parameters sourced from a file the gate cannot read.
CLI_INPUT_FILE = re.compile(r"--cli-input-(?:json|yaml)[=\s]\s*[\"']?file://")

CLASS_RANK = {"read": 0, "execute": 1, "create": 2, "modify": 2, "destroy": 3}

# ---------------------------------------------------------------------------
# Local decision ledger (metadata only; best-effort; never blocks the gate).
# ---------------------------------------------------------------------------
LEDGER_KEYS = (
    "ts",
    "service",
    "operation",
    "class",
    "sensitive",
    "decision",
    "stamp",
    "profile",
    "profile_class",
)
_LEDGER = []
_LEDGER_ENABLED = True
_LEDGER_PATH = os.environ.get("AWS_OPS_LEDGER_FILE") or os.path.expanduser(
    "~/.claude/aws-ops-ledger.jsonl"
)


def ledger_record(service, op, cls, sensitive, stamp, profile, profile_class):
    """Create and retain one ledger entry per inspected invocation.

    Only classification metadata is stored: no raw command text, argument
    values, tag values, or secret material ever reaches the ledger.
    """
    rec = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "service": service,
        "operation": op,
        "class": cls,
        "sensitive": bool(sensitive),
        "decision": "allow",
        "stamp": stamp if stamp else None,
        "profile": profile if profile else None,
        "profile_class": profile_class if profile_class else None,
    }
    _LEDGER.append(rec)
    return rec


def ledger_flush():
    """Append all retained entries, one JSON object per line. Best-effort:
    a ledger failure must never raise, delay, or change the gate decision."""
    try:
        if not _LEDGER_ENABLED or not _LEDGER:
            return
        # Create the metadata-only ledger as owner-readable/writable. ``open``
        # alone would honor a permissive umask and can leave it world-readable.
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        elif Path(_LEDGER_PATH).is_symlink():
            return
        if hasattr(os, "O_NONBLOCK"):
            # A FIFO must not stall a blocking decision until the hook timeout.
            flags |= os.O_NONBLOCK
        fd = os.open(_LEDGER_PATH, flags, 0o600)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_nlink != 1:
            os.close(fd)
            return
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            for rec in _LEDGER:
                fh.write(json.dumps({k: rec.get(k) for k in LEDGER_KEYS}) + "\n")
    except Exception:
        pass


def decision(action, reason, rec=None):
    if CODEX_RUNTIME and action == "ask":
        action = "deny"
        reason = (
            "Blocked fail-closed: this operation requires confirmation, and "
            "Codex hook decisions cannot safely pause on 'ask'. " + reason
        )
    if rec is not None:
        rec["decision"] = action
    if action == "deny":
        # A deny blocks the entire Bash command: nothing in it runs. Record
        # every retained entry as denied so the ledger never shows an allow
        # line for a command that never reached AWS.
        for r in _LEDGER:
            r["decision"] = "deny"
    ledger_flush()
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": action,
                    "permissionDecisionReason": reason,
                }
            }
        )
    )
    sys.exit(0)


def load_policy():
    path = os.environ.get(
        "AWS_OPS_POLICY_FILE",
        os.path.expanduser("~/.claude/aws-ops.policy.json"),
    )
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def load_policy_checked():
    """Return (policy, error) for the Codex fail-closed lane."""
    path = Path(
        os.environ.get(
            "AWS_OPS_POLICY_FILE",
            os.path.expanduser("~/.claude/aws-ops.policy.json"),
        )
    ).expanduser()
    try:
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        elif path.is_symlink():
            return None, "private policy must not be a symbolic link"
        if hasattr(os, "O_NONBLOCK"):
            # A FIFO must not stall the hook until the host kills it fail-open.
            flags |= os.O_NONBLOCK
        fd = os.open(path, flags)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            os.close(fd)
            return None, "private policy must be a regular file"
        if st.st_uid != os.getuid():
            os.close(fd)
            return None, "private policy must be owned by the current user"
        if st.st_size > MAX_POLICY_BYTES:
            os.close(fd)
            return None, f"private policy exceeds {MAX_POLICY_BYTES} bytes"
        if st.st_mode & 0o777 != 0o600:
            os.close(fd)
            return (
                None,
                f"policy permissions must be 600 (found {st.st_mode & 0o777:03o})",
            )
        with os.fdopen(fd, encoding="utf-8") as fh:
            policy = json.load(fh)
    except (OSError, ValueError) as exc:
        return None, f"private policy is unavailable or invalid ({type(exc).__name__})"
    if not isinstance(policy, dict):
        return None, "private policy top level must be a JSON object"
    profiles = policy.get("profiles")
    operator = policy.get("operator")
    if not isinstance(profiles, dict) or not profiles:
        return None, "private policy must classify at least one profile"
    if any(
        v not in {"readonly", "admin", "frozen", "personal"} for v in profiles.values()
    ):
        return None, "private policy contains an unsupported profile class"
    if "readonly" not in profiles.values():
        return None, "private policy must classify at least one readonly profile"
    if not isinstance(operator, dict):
        return None, "private policy operator must be a JSON object"
    prefix = operator.get("stamp_prefix")
    if not isinstance(prefix, str) or not prefix.strip():
        return None, "private policy must define operator.stamp_prefix"
    if not CODEX_STAMP.fullmatch(prefix.strip()):
        return None, "private policy stamp prefix must be lowercase kebab-case"
    required_tags = policy.get("required_tags", {})
    if not isinstance(required_tags, dict):
        return None, "private policy required_tags must be a JSON object"
    allowed_environment = policy.get("allowed_environment", {})
    if not isinstance(allowed_environment, dict):
        return None, "private policy allowed_environment must be a JSON object"
    if any(name not in CODEX_POLICY_ALLOWLIST_ENV for name in allowed_environment):
        return None, "private policy allowed_environment contains an unsupported key"
    if any(
        not isinstance(value, str) or not value
        for value in allowed_environment.values()
    ):
        return (
            None,
            "private policy allowed_environment values must be non-empty strings",
        )
    return policy, None


def load_inventory():
    """Load the packaged inventory without blocking on hostile file types."""
    table = {}
    fd = None
    try:
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        elif INVENTORY_PATH.is_symlink():
            return table
        if hasattr(os, "O_NONBLOCK"):
            # A damaged cache containing a FIFO must fail closed before the
            # hook host's timeout can turn the failure into an allowed call.
            flags |= os.O_NONBLOCK
        fd = os.open(INVENTORY_PATH, flags)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_INVENTORY_BYTES:
            os.close(fd)
            fd = None
            return table
        with os.fdopen(fd, newline="", encoding="utf-8") as fh:
            fd = None
            for row in csv.reader(fh):
                if len(row) >= 4 and row[0] != "service":
                    paginated = len(row) >= 6 and row[5] == "1"
                    table[(row[0], row[1])] = (
                        row[2],
                        row[3] == "1",
                        paginated,
                    )
    except (OSError, UnicodeError, csv.Error):
        pass
    finally:
        if fd is not None:
            os.close(fd)
    return table


def codex_aws_alias_error():
    """Reject AWS CLI aliases that can replace otherwise approved commands."""
    path = Path.home() / ".aws" / "cli" / "alias"
    fd = None
    try:
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        elif path.is_symlink():
            return "the AWS CLI alias file must not be a symbolic link"
        if hasattr(os, "O_NONBLOCK"):
            flags |= os.O_NONBLOCK
        fd = os.open(path, flags)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return "the AWS CLI alias file must be a regular file"
        if st.st_uid != os.getuid():
            return "the AWS CLI alias file must be owned by the current user"
        if st.st_size > MAX_AWS_ALIAS_BYTES:
            return f"the AWS CLI alias file exceeds {MAX_AWS_ALIAS_BYTES} bytes"
        with os.fdopen(fd, encoding="utf-8") as fh:
            fd = None
            text = fh.read(MAX_AWS_ALIAS_BYTES + 1)
    except FileNotFoundError:
        return None
    except (OSError, UnicodeError) as exc:
        return f"the AWS CLI alias file is unsafe or unreadable ({type(exc).__name__})"
    finally:
        if fd is not None:
            os.close(fd)
    active = [
        line
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith(("#", ";"))
    ]
    if active:
        return "AWS CLI aliases are configured and can replace approved commands"
    return None


def classify_op(service, op, inventory):
    if service in ("help", "history") or op in ("help", "wait"):
        return "read", False
    if service == "configure":
        return ("read", True) if op == "export-credentials" else ("read", False)
    hit = inventory.get((service, op))
    if hit:
        return hit[0], hit[1]
    verb = op.split("-", 1)[0]
    if verb in ("batch", "admin") and "-" in op:
        verb = op.split("-", 2)[1]
    if verb == "assume":
        return "read", True
    cls = VERB_CLASS.get(verb)
    if cls is None:
        return "modify", True  # unknown verb: guarded mutation
    return cls, cls == "destroy"


def parse_invocation(tokens, start):
    """From tokens[start] == aws, return (service, operation, profile, stamp)."""
    profile = None
    stamp = None
    for t in tokens[:start]:
        if t.startswith(STAMP_VAR + "="):
            # Strip whitespace as well as quotes: a stamp of only spaces is not
            # a purpose stamp, and must fall through to the unstamped-mutation
            # deny rather than passing as a truthy value.
            stamp = t.split("=", 1)[1].strip().strip("'\"").strip()
        m = re.match(r"AWS_PROFILE=(\S+)", t)
        if m:
            profile = m.group(1).strip("'\"")
    words = []
    i = start + 1
    while i < len(tokens):
        t = tokens[i]
        if t in ("&&", "||", ";", "|"):
            break
        if t.startswith("--"):
            flag = canonical_aws_global_flag(t)
            if flag == "--profile":
                profile = (
                    t.split("=", 1)[1]
                    if "=" in t
                    else (tokens[i + 1] if i + 1 < len(tokens) else None)
                )
            if flag in VALUE_FLAGS and "=" not in t:
                i += 2
                continue
            i += 1
            continue
        if not t.startswith("-") and len(words) < 2:
            # First two positional tokens are service and operation; keep
            # scanning afterwards so a trailing --profile is still seen.
            words.append(t)
        i += 1
    service = words[0] if words else None
    op = words[1] if len(words) > 1 else ("help" if service == "help" else "")
    if service in (None, "--version", "-v"):
        service, op = "help", "help"
    return service, op, profile, stamp


def explicit_flag_value(tokens, start, wanted):
    """Return the last explicit value, matching AWS CLI override behavior."""
    found = None
    i = start + 1
    while i < len(tokens):
        token = tokens[i]
        if token in ("&&", "||", ";", "|"):
            break
        name, separator, inline = token.partition("=")
        if canonical_aws_global_flag(name) == wanted:
            if separator:
                found = inline
                i += 1
                continue
            found = tokens[i + 1] if i + 1 < len(tokens) else None
            i += 2
            continue
        i += 1
    return found


def inline_assignment(tokens, start, name, value=None):
    """Check the last NAME=value before this invocation (shell precedence)."""
    prefix = name + "="
    found = None
    for token in tokens[:start]:
        if not token.startswith(prefix):
            continue
        found = token.split("=", 1)[1].strip("'\"")
    return found is not None and (value is None or found == value)


def codex_brace_variants(value, limit=32):
    """Expand a small literal shell-brace expression for AWS path detection."""
    variants = [value]
    while len(variants) <= limit:
        expanded = False
        next_variants = []
        for variant in variants:
            match = re.search(r"\{([^{}]*,[^{}]*)\}", variant)
            if not match:
                next_variants.append(variant)
                continue
            expanded = True
            for option in match.group(1).split(","):
                next_variants.append(
                    variant[: match.start()] + option + variant[match.end() :]
                )
                if len(next_variants) > limit:
                    return []
        variants = next_variants
        if not expanded:
            return variants
    return []


def codex_shell_expanded_aws_word(token):
    """Detect a command word that shell expansion can turn into an AWS CLI."""
    if not CODEX_READ_ONLY or not re.search(r"[*?\[\](){}]", token):
        return False
    candidates = codex_brace_variants(token) or [token]
    trusted = os.path.normpath(TRUSTED_AWS_CLI)
    for candidate in candidates:
        # zsh appends glob qualifiers such as ``(N)`` or ``(@)`` after the
        # pathname pattern. Strip that suffix before matching the executable.
        pathname = re.sub(r"\([^/]*\)\Z", "", candidate)
        basename = os.path.basename(pathname)
        # ``fnmatch`` covers pathname globs such as aw?, a*, and a[w]s.
        if fnmatch.fnmatchcase("aws", basename) or fnmatch.fnmatchcase(
            trusted, pathname
        ):
            return True
    return False


def is_aws_token(token):
    """Whether a shell token names the AWS CLI executable."""
    if SHELL_ASSIGNMENT.fullmatch(token):
        return False
    if codex_shell_expanded_aws_word(token):
        return True
    if token == "aws" or (token.endswith("/aws") and "://" not in token):
        return True
    if CODEX_READ_ONLY and "/" in token and "://" not in token:
        try:
            return os.path.realpath(token) == os.path.realpath(TRUSTED_AWS_CLI)
        except (OSError, ValueError):
            return False
    return False


def command_word_index(tokens):
    """Return the direct command word after leading shell assignments."""
    for index, token in enumerate(tokens):
        if not SHELL_ASSIGNMENT.fullmatch(token):
            return index
    return None


def codex_execution_wrapper(token):
    """Whether a command word can execute or dispatch a later argument/body."""
    executable = os.path.basename(token)
    return (
        token.startswith("$")
        or token.startswith("\x60")
        or executable in CODEX_EXECUTION_WRAPPERS
        or bool(
            re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\(\)\{?", executable)
            or re.match(r"^(?:\d*)?(?:<|>>?|<>|>\||<&|>&)", token)
        )
    )


def codex_wrapped_text_command(tokens, index):
    """Recognize `env ... <text-tool> aws` where aws is inert search data."""
    if index is None or os.path.basename(tokens[index]) != "env":
        return False
    nested_index = index + 1
    while nested_index < len(tokens) and (
        tokens[nested_index].startswith("-")
        or SHELL_ASSIGNMENT.fullmatch(tokens[nested_index])
    ):
        nested_index += 1
    return (
        nested_index < len(tokens)
        and os.path.basename(tokens[nested_index]) in CODEX_TEXT_ARGUMENT_COMMANDS
    )


def codex_prefix_assignment_error(tokens, start):
    """Reject every Codex prefix assignment except the two protocol fields."""
    for token in tokens[:start]:
        match = SHELL_ASSIGNMENT.fullmatch(token)
        if not match:
            return "AWS CLI wrappers and shell control words are not allowed"
        if match.group(1) not in CODEX_ALLOWED_PREFIX_ASSIGNMENTS:
            return (
                f"inline assignment {match.group(1)} is not allowed before the "
                "Codex AWS CLI"
            )
    return None


def codex_literal_flag_value(value):
    """True only for a non-empty scalar flag value with no shell expansion."""
    if not isinstance(value, str) or not value or value.startswith("-"):
        return False
    return not re.search(r"[$\x60;|&<>(){}]", value)


def canonical_aws_global_flag(token):
    """Resolve the unique long-option abbreviations accepted by AWS argparse."""
    name = token.partition("=")[0]
    if name in AWS_GLOBAL_FLAGS or not name.startswith("--") or len(name) <= 2:
        return name
    matches = [full for full in AWS_GLOBAL_FLAGS if full.startswith(name)]
    return matches[0] if len(matches) == 1 else name


def codex_forbidden_global_flag(token):
    """Match a forbidden global flag or any argparse-style abbreviation."""
    return canonical_aws_global_flag(token) in CODEX_FORBIDDEN_GLOBAL_FLAGS


def codex_abbreviated_guard_flag(token):
    """Reject abbreviations of flags that uphold Codex read-only invariants."""
    name = token.partition("=")[0]
    if not name.startswith("--") or len(name) <= 2 or name in CODEX_EXACT_ONLY_FLAGS:
        return False
    return any(full.startswith(name) for full in CODEX_EXACT_ONLY_FLAGS)


def command_has_global_flag(command, wanted):
    """Find an AWS global flag, including a unique argparse abbreviation."""
    for segment in re.split(r"[;\r\n]|&&|\|\||\||&(?!&)", command):
        if any(
            canonical_aws_global_flag(token) == wanted for token in tokenize(segment)
        ):
            return True
    return False


def guarded_operation_flag(tokens, full_name, minimum_prefix):
    """Match an exact high-impact operation flag or a plausible abbreviation."""
    for token in tokens:
        name = token.partition("=")[0]
        if name == full_name:
            return True
        if len(name) >= len(minimum_prefix) and full_name.startswith(name):
            return True
    return False


def codex_command_complexity_error(command):
    """Bound recursive shell scanning before any potentially superlinear work."""
    if len(command) > MAX_CODEX_COMMAND_CHARS:
        return f"command exceeds {MAX_CODEX_COMMAND_CHARS} characters"
    substitution_markers = sum(
        command.count(marker) for marker in ("$(", "<(", ">(", "\x60")
    )
    if substitution_markers > MAX_CODEX_SUBSTITUTION_MARKERS:
        return (
            "command contains too many command/process substitutions "
            f"({substitution_markers} > {MAX_CODEX_SUBSTITUTION_MARKERS})"
        )
    segment_markers = sum(command.count(marker) for marker in (";", "\n", "|", "&"))
    if segment_markers > MAX_CODEX_SEGMENT_MARKERS:
        return (
            "command contains too many shell segments "
            f"({segment_markers} > {MAX_CODEX_SEGMENT_MARKERS})"
        )
    shell_wrappers = len(
        re.findall(r"(?<![A-Za-z0-9_/])(?:sh|bash|zsh|dash|ksh|ash)\b", command)
    )
    if shell_wrappers > MAX_CODEX_SHELL_WRAPPERS:
        return (
            "command contains too many nested shell wrappers "
            f"({shell_wrappers} > {MAX_CODEX_SHELL_WRAPPERS})"
        )
    return None


def codex_dynamic_word_matches_aws(word):
    """Whether shell expansion can turn one token into the trusted AWS CLI."""
    trusted = os.path.normpath(TRUSTED_AWS_CLI)
    if not isinstance(word, str) or not ("$" in word or "\x60" in word):
        return False
    if word.startswith("$") and "\\" in word:
        try:
            decoded = bytes(word[1:], "utf-8").decode("unicode_escape")
        except (UnicodeDecodeError, UnicodeEncodeError, ValueError):
            decoded = ""
        if decoded and is_aws_token(decoded):
            return True
    pattern = re.sub(r"\$\([^)]*\)|\x60[^\x60]*\x60", "*", word)
    pattern = re.sub(
        r"\$\{[^}]*\}|\$(?:[@*#?$!_-]|[0-9]+|[A-Za-z_][A-Za-z0-9_]*)",
        "*",
        pattern,
    )
    basename_pattern = os.path.basename(pattern)
    return basename_pattern != "*" and (
        fnmatch.fnmatchcase(trusted, pattern)
        or fnmatch.fnmatchcase("aws", basename_pattern)
    )


def codex_unsafe_dynamic_command_word(command):
    """Find a dynamic command word that can resolve to the AWS CLI."""
    for segment in re.split(r"[;\r\n]|&&|\|\||\||&(?!&)", command):
        tokens = tokenize(segment)
        index = command_word_index(tokens)
        if index is None:
            continue
        word = tokens[index]
        if word.startswith("="):
            if word == "=aws" or word.endswith("/aws"):
                return "zsh =command lookup"
            continue
        if "$" in word or "\x60" in word:
            if "aws" in re.sub(r"[\"']", "", segment).lower():
                return "parameter or command substitution in the command word"
            if codex_dynamic_word_matches_aws(word):
                return "parameter or command substitution in the command word"
    return None


def codex_dynamic_aws_invocation(command):
    """Detect simple variable-built AWS command words and deny them.

    This recognizes literal assignments and simple shell variable expansion.
    It catches common accidental indirection without pretending to be a
    complete shell interpreter.
    """
    values = {}
    variable = re.compile(
        r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))"
    )
    for segment in re.split(r"[;\r\n]|&&|\|\||\||&(?!&)", command):
        tokens = tokenize(segment)
        if not tokens:
            continue
        if os.path.basename(tokens[0]) == "unset":
            for name in tokens[1:]:
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                    values.pop(name, None)
            continue
        for token in tokens:
            match = SHELL_ASSIGNMENT.fullmatch(token)
            if match:
                values[match.group(1)] = match.group(2)
        index = command_word_index(tokens)
        if index is None:
            continue
        word = tokens[index]

        def expand(match):
            name = match.group(1) or match.group(2)
            return values.get(name, os.environ.get(name, match.group(0)))

        expanded = variable.sub(expand, word)
        if expanded != word and is_aws_token(expanded):
            return True
    return False


def codex_indirect_aws_wrapper(command):
    """Detect an execution wrapper around AWS even when AWS is quoted data."""
    aws_data_seen = False
    pipeline_executor_seen = False
    for segment in re.split(r"[;\r\n]|&&|\|\||\||&(?!&)", command):
        tokens = tokenize(segment)
        if any(is_aws_token(token) for token in tokens):
            aws_data_seen = True
        index = command_word_index(tokens)
        if index is None:
            continue
        executable = tokens[index]
        executable_name = os.path.basename(executable)
        if executable_name in CODEX_PIPELINE_EXECUTORS:
            pipeline_executor_seen = True
        if executable_name in CODEX_EXECUTABLE_PREPARATION:
            for token in tokens[index + 1 :]:
                candidate = token.split("=", 1)[1] if "=" in token else token
                if is_aws_token(candidate) or codex_dynamic_word_matches_aws(candidate):
                    return True
        if not codex_execution_wrapper(executable):
            continue
        nested_index = index + 1
        if codex_wrapped_text_command(tokens, index):
            continue
        if any(is_aws_token(token) for token in tokens[nested_index:]):
            return True
        if (
            executable_name in CODEX_BODY_EXECUTION_WRAPPERS
            and "aws" in re.sub(r"[\"']", "", segment).lower()
        ):
            return True
    # Data-producing and data-consuming pipeline segments are parsed
    # independently. Correlate them so `printf /trusted/aws | xargs ...` (or
    # `which aws | xargs ...`) cannot hide the executable from the direct-path
    # check merely by putting it in an earlier segment.
    return aws_data_seen and pipeline_executor_seen


# A resource-NAME flag the operator uses to name something they create:
# --name, --stack-name, --function-name, --role-name, --bucket, ... Deliberately
# limited to --name / *-name / --bucket so a marker in a name the operator is
# ASSIGNING is caught (hard prohibition #7) without scanning every id-like flag.
NAME_FLAG = re.compile(r"^--(?:name|bucket|[a-z][a-z0-9-]*-name)$")


def name_flag_values(tokens, start):
    """Values of resource-name flags on the invocation beginning at tokens[start]
    (--flag=value and --flag value both handled), so a tool/automation marker in
    a name is caught like one in a tag value."""
    vals = []
    i = start + 1
    while i < len(tokens):
        t = tokens[i]
        if t in ("&&", "||", ";", "|"):
            break
        if t.startswith("--"):
            flag, sep, inline = t.partition("=")
            if NAME_FLAG.match(flag):
                if sep:
                    vals.append(inline)
                elif i + 1 < len(tokens) and not tokens[i + 1].startswith("-"):
                    vals.append(tokens[i + 1])
        i += 1
    return vals


def tokenize(segment):
    try:
        import shlex

        return shlex.split(segment, posix=True)
    except ValueError:
        return segment.split()


def strip_invisibles(value):
    """Remove Unicode format/control characters (soft hyphen U+00AD,
    zero-width space U+200B, BOM, ...) that render invisibly but split a
    marker token so it dodges the word-boundary and separator passes."""
    return "".join(
        ch for ch in (value or "") if unicodedata.category(ch) not in ("Cf", "Cc")
    )


# High-confidence Cyrillic/Greek look-alikes of the Latin letters used in the
# markers, folded back to Latin so a homoglyph stamp/tag ("clаude" with a
# Cyrillic 'а") cannot dodge the marker checks. NFKC (applied first) already
# folds fullwidth/compatibility forms; this table covers the script-confusables
# NFKC leaves alone. Kept to letters that actually appear in the markers.
_CONFUSABLES = {
    # Cyrillic -> Latin
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "х": "x",
    "у": "y",
    "і": "i",
    "ј": "j",
    "ѕ": "s",
    "ԁ": "d",
    "һ": "h",
    "ӏ": "l",
    "ԛ": "q",
    "ԍ": "g",
    "т": "t",
    "н": "h",
    "к": "k",
    "м": "m",
    # Greek -> Latin
    "α": "a",
    "ϲ": "c",
    "ε": "e",
    "ι": "i",
    "ο": "o",
    "ρ": "p",
    "τ": "t",
    "ν": "v",
    "υ": "u",
    "ɡ": "g",
}
_CONFUSABLE_TABLE = str.maketrans(_CONFUSABLES)


def canon_fold(value):
    """Normalize an audit-visible value to the ASCII the marker checks expect:
    strip invisibles, apply NFKC (folds fullwidth/compatibility forms),
    lower-case, then fold high-confidence script-confusables to Latin. So a
    fullwidth or Cyrillic/Greek look-alike spelling of a marker collapses to the
    same string an ASCII marker would."""
    normalized = unicodedata.normalize("NFKC", strip_invisibles(value or "")).lower()
    return normalized.translate(_CONFUSABLE_TABLE)


# Per-brand obfuscation patterns: the brand's letters in order, allowing
# separators between them (invisibles are already stripped by canon_fold), but
# ANCHORED so the match is a whole word rather than a coincidental substring of a
# longer one. This catches c-l-a-u-d-e, cl.aude, and open_ai, while leaving
# ordinary hyphenated words clean (open-air, geminide-..., scope-nairobi) --
# their brand letters run into more letters, so the trailing anchor fails.
_BRAND_PATTERNS = [
    re.compile(r"(?<![a-z0-9])" + r"[-_.\s]*".join(tok) + r"(?![a-z0-9])")
    for tok in BRAND_TOKENS
]


def brand_marker_hit(value):
    """Second marker pass: canonicalize (NFKC + homoglyph fold + lowercase), then
    look for a brand token whose letters appear in order and separator-delimited,
    anchored as a whole word -- so xx-c-l-a-u-d-e-run, a soft-hyphen variant, a
    Cyrillic-lookalike, and open_ai are denied, while ordinary words (claudia,
    open-air, geminide-...) stay clean."""
    v = canon_fold(value)
    return any(p.search(v) for p in _BRAND_PATTERNS)


def extract_substitutions(text):
    """Return the bodies of command and process substitutions found anywhere in
    the command -- $(...), `...`, and the process substitutions <(...) / >(...)
    -- so a nested aws invocation is classified even when quoting or a process
    substitution hides it from the token scan. Scanning the whole text also
    reaches substitutions nested inside other substitutions."""
    bodies = []
    for m in re.finditer(r"`([^`]+)`", text):
        bodies.append(m.group(1))
    # $(...), <(...), >(...): a two-character opener ending in '(' followed by a
    # balanced-paren body. bash executes the body of a process substitution, so
    # an aws call inside <(...) / >(...) must be classified exactly like one in
    # $(...) -- otherwise it bypasses the gate entirely.
    for opener in ("$(", "<(", ">("):
        i = 0
        while True:
            i = text.find(opener, i)
            if i == -1:
                break
            depth = 1
            j = i + 2
            while j < len(text) and depth:
                if text[j] == "(":
                    depth += 1
                elif text[j] == ")":
                    depth -= 1
                j += 1
            # Unterminated substitution: take the rest (errs strict).
            bodies.append(text[i + 2 : j - 1] if depth == 0 else text[i + 2 :])
            i += 2
    return [b for b in bodies if b.strip()]


def shell_words(text):
    """Minimal quote-aware word split that NEVER raises. Quotes group spaces;
    an unterminated quote reads to end-of-string (errs strict); everything else
    splits on whitespace. Used to locate a shell -c / here-string body even in a
    command a strict lexer would reject -- e.g. an unbalanced quote inside a
    trailing `# comment` that the real shell ignores but shlex.split chokes on
    (which would otherwise let `bash -c '...aws...' # "x` fail open)."""
    words, i, n = [], 0, len(text)
    while i < n:
        while i < n and text[i].isspace():
            i += 1
        if i >= n:
            break
        buf = []
        while i < n and not text[i].isspace():
            c = text[i]
            if c in "'\"":
                i += 1
                while i < n and text[i] != c:
                    buf.append(text[i])
                    i += 1
                i += 1  # past the closing quote (or past end if unterminated)
            else:
                buf.append(c)
                i += 1
        words.append("".join(buf))
    return words


# Inline shells whose -c argument (or here-string) is an executable script.
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "ash"}
# Long options that consume the following token as their value (so it is not
# mistaken for the -c script): bash --rcfile FILE / --init-file FILE.
SHELL_VALUE_OPTS = {"--rcfile", "--init-file"}


def extract_shell_c(text):
    """Return the script bodies an inline shell would execute: the argument of a
    -c option (``bash -c '<script>'``, ``sh -lc ...``) and a spaced here-string
    (``bash <<< '<script>'``), so an aws call hidden inside the quoted script is
    scanned like a substitution body. Never raises; the lenient word split means
    a trailing comment with an unbalanced quote cannot make it fail open, and a
    long option like --rcfile is not mistaken for the -c cluster."""
    toks = shell_words(text)
    bodies = []
    i = 0
    while i < len(toks):
        if toks[i].rsplit("/", 1)[-1] in SHELLS:
            j, saw_c = i + 1, False
            while j < len(toks):
                t = toks[j]
                if t == "<<<":  # here-string: the next word is the script
                    if j + 1 < len(toks):
                        bodies.append(toks[j + 1])
                    break
                if t == "--":
                    j += 1
                    break
                if t.startswith("--"):
                    j += 2 if t in SHELL_VALUE_OPTS else 1
                    continue
                if t.startswith(("-", "+")):
                    # -c with the script FUSED onto the option token
                    # (-c'...', -lc"..." -> shell_words yields -cscript): the
                    # remainder after the c is the script.
                    m = re.match(r"[-+][a-z]*c(.+)$", t, re.IGNORECASE)
                    if m:
                        bodies.append(m.group(1))
                        saw_c = True
                        break
                    # A short cluster carrying 'c' (-c, -lc): the next positional
                    # is the script.
                    if "c" in t.lower():
                        saw_c = True
                    # -o/+o <mode>, -O <shopt> take the next token as their value,
                    # which must not be mistaken for the -c script.
                    j += 2 if re.search(r"[oO]$", t) else 1
                    continue
                break  # first positional token: the -c script, if one was seen
            if saw_c and j < len(toks):
                bodies.append(toks[j])
        i += 1
    return [b for b in bodies if b.strip()]


def update_carried_profile(tokens, carried):
    """Track AWS_PROFILE assignments that persist in the shell: ``export
    AWS_PROFILE=...`` and bare assignment segments (no command word). Inline
    per-command assignments (AWS_PROFILE=x aws ...) apply only to their own
    invocation and are handled by parse_invocation. ``unset AWS_PROFILE``
    clears the carried value."""
    n = len(tokens)
    has_command = any(
        "=" not in t and t not in ("export", "env", "unset") and not t.startswith("-")
        for t in tokens
    )
    for i, t in enumerate(tokens):
        if t == "unset" and i + 1 < n and tokens[i + 1] == "AWS_PROFILE":
            carried = None
            continue
        m = re.match(r"^AWS_PROFILE=(.+)$", t)
        if m:
            exported = "export" in tokens[max(0, i - 3) : i]
            if exported or not has_command:
                carried = m.group(1).strip("'\"")
    return carried


def codex_persistent_context_override(command):
    """Detect shell context changes that persist into a later AWS segment."""

    def sensitive_name(name):
        return (
            name in CODEX_CONTEXT_ENV
            or name in UNSAFE_INHERITED_AWS_ENV
            or name.startswith("AWS_")
            or name.startswith("AWS_ENDPOINT_URL_")
            or name.startswith("DYLD_")
        )

    for segment in re.split(r"[;\r\n]|&&|\|\||\||&(?!&)", command):
        tokens = tokenize(segment)
        if not tokens:
            continue
        index = command_word_index(tokens)
        if index is None:
            if any(
                (match := SHELL_ASSIGNMENT.fullmatch(token))
                and sensitive_name(match.group(1))
                for token in tokens
            ):
                return True
            continue
        executable = os.path.basename(tokens[index])
        if executable == "unset":
            if any(sensitive_name(name) for name in tokens[index + 1 :]):
                return True
            continue
        exporting = executable in {"export", "readonly"} or (
            executable in {"declare", "typeset"} and "-x" in tokens[index + 1 :]
        )
        if exporting and any(
            (match := SHELL_ASSIGNMENT.fullmatch(token))
            and sensitive_name(match.group(1))
            for token in tokens[index + 1 :]
        ):
            return True
        args = tokens[index + 1 :]
        if executable == "set" and (
            "-a" in args
            or "allexport" in args
            or any(
                args[position] == "-o" and args[position + 1] == "allexport"
                for position in range(len(args) - 1)
            )
        ):
            return True
    return False


def codex_aws_execution_intent(command):
    """Discover an executable AWS candidate before policy/environment checks."""
    if (
        codex_dynamic_aws_invocation(command)
        or codex_indirect_aws_wrapper(command)
        or codex_unsafe_dynamic_command_word(command)
    ):
        return True
    units, seen, queue = [], set(), [command]
    while queue and len(units) < 4096:
        unit = queue.pop(0)
        if unit in seen:
            continue
        seen.add(unit)
        units.append(unit)
        for body in list(extract_substitutions(unit)) + list(extract_shell_c(unit)):
            if body not in seen:
                queue.append(body)
    for unit in units:
        unit = re.sub(r"\\\r?\n", " ", unit)
        for segment in re.split(r"[;\r\n]|&&|\|\||\||&(?!&)", unit):
            tokens = tokenize(segment)
            index = command_word_index(tokens)
            if index is None:
                continue
            if is_aws_token(tokens[index]):
                return True
            if codex_execution_wrapper(tokens[index]) and any(
                is_aws_token(token) for token in tokens[index + 1 :]
            ):
                return True
    return False


def main():
    global _LEDGER_ENABLED
    raw_event = sys.stdin.read()
    try:
        event = json.loads(raw_event)
    except (TypeError, ValueError):
        if CODEX_RUNTIME:
            decision(
                "deny",
                "Blocked fail-closed: the Codex Bash hook event was not valid JSON.",
            )
        sys.exit(0)
    if not isinstance(event, dict):
        if CODEX_RUNTIME:
            decision(
                "deny",
                "Blocked fail-closed: the Codex Bash hook event must be a JSON object.",
            )
        sys.exit(0)
    if event.get("tool_name") != "Bash":
        sys.exit(0)
    tool_input = event.get("tool_input")
    if not isinstance(tool_input, dict):
        if CODEX_RUNTIME:
            decision(
                "deny",
                "Blocked fail-closed: the Codex Bash hook input is malformed.",
            )
        sys.exit(0)
    cmd = tool_input.get("command") or ""
    if not isinstance(cmd, str):
        if CODEX_RUNTIME:
            decision(
                "deny",
                "Blocked fail-closed: the Codex Bash command must be text.",
            )
        sys.exit(0)
    if CODEX_READ_ONLY and tool_input.get("tty") is True:
        decision(
            "deny",
            "Blocked fail-closed: interactive PTY commands are disabled while the "
            "Codex AWS guard is active because later write_stdin input does not "
            "receive another PreToolUse check.",
        )
    # Discover a real executable candidate before loading private policy or
    # rejecting inherited AWS environment. Plain documentation/search text that
    # merely contains "aws" must remain outside the gate.
    if CODEX_READ_ONLY:
        complexity_error = codex_command_complexity_error(cmd)
        if complexity_error:
            shallow_evidence = "aws" in re.sub(r"[\"']", "", cmd).lower()
            shallow_evidence = (
                shallow_evidence
                or codex_dynamic_aws_invocation(cmd)
                or bool(codex_unsafe_dynamic_command_word(cmd))
            )
            if not shallow_evidence:
                sys.exit(0)
            decision(
                "deny",
                "Blocked fail-closed: shell command complexity exceeds the "
                f"Codex AWS gate limits ({complexity_error}). Split it into "
                "smaller, directly inspectable commands.",
            )
        codex_dynamic = codex_dynamic_aws_invocation(cmd)
        if not codex_aws_execution_intent(cmd):
            sys.exit(0)
        dynamic_word_error = codex_unsafe_dynamic_command_word(cmd)
        if dynamic_word_error:
            decision(
                "deny",
                "Blocked fail-closed: dynamic command names are not allowed in "
                f"the Codex read-only lane ({dynamic_word_error}). Use a literal "
                "executable path.",
            )
    else:
        codex_dynamic = False
        if "aws" not in re.sub(r"[\"']", "", cmd).lower():
            sys.exit(0)

    if CODEX_READ_ONLY:
        policy, policy_error = load_policy_checked()
        if policy_error:
            decision("deny", f"Blocked fail-closed: {policy_error}.")
        allowed_environment = policy.get("allowed_environment", {})
        inherited = [name for name in UNSAFE_INHERITED_AWS_ENV if os.environ.get(name)]
        inherited += [
            name for name in UNSAFE_INHERITED_RUNTIME_ENV if os.environ.get(name)
        ]
        inherited += [
            name
            for name, value in os.environ.items()
            if (
                (name.startswith("AWS_") and name not in CODEX_INTERNAL_AWS_ENV)
                or name.startswith("DYLD_")
                or name.startswith("BASH_FUNC_")
            )
            and value
        ]
        launch_context = os.environ.get("AWS_OPS_UNSAFE_LAUNCH_ENV", "")
        inherited += [name for name in launch_context.split(",") if name]
        inherited += [
            name
            for name in CODEX_POLICY_ALLOWLIST_ENV
            if os.environ.get(name)
            and allowed_environment.get(name) != os.environ.get(name)
        ]
        inherited = sorted(set(inherited))
        if inherited:
            decision(
                "deny",
                "Blocked fail-closed: inherited AWS environment overrides are set "
                f"({', '.join(inherited)}). Start the task with a clean AWS environment.",
            )
        if codex_persistent_context_override(cmd):
            decision(
                "deny",
                "Blocked fail-closed: the command persistently changes AWS, HOME, "
                "PATH, loader, runtime, or TLS context around the Codex AWS CLI.",
            )
        alias_error = codex_aws_alias_error()
        if alias_error:
            decision("deny", f"Blocked fail-closed: {alias_error}.")
    else:
        policy = load_policy()
    _LEDGER_ENABLED = policy.get("ledger") is not False
    profiles = policy.get("profiles") or {}
    stamp_prefix = ((policy.get("operator") or {}).get("stamp_prefix") or "").strip()
    required_tags = policy.get("required_tags") or {}
    # frozen_accounts holds account IDs (advisory: the gate can't resolve a
    # profile to an account without calling AWS) OR profile names. When a
    # resolved profile NAME matches an entry, treat it as frozen -- a
    # defense-in-depth deny that only ever adds strictness.
    frozen_names = {
        str(x)
        for x in (policy.get("frozen_accounts") or [])
        if isinstance(x, (str, int))
    }
    inventory = load_inventory()

    if CODEX_READ_ONLY and not inventory:
        decision(
            "deny",
            "Blocked fail-closed: the AWS operation inventory is missing or unreadable.",
        )

    if CODEX_READ_ONLY and codex_indirect_aws_wrapper(cmd):
        decision(
            "deny",
            "Blocked fail-closed: wrappers, dispatchers, dynamic shells, and "
            "indirect execution around the Codex AWS CLI are not allowed.",
        )

    if command_has_global_flag(cmd, "--no-verify-ssl"):
        decision(
            "deny",
            "TLS verification must never be disabled (--no-verify-ssl). Remove the flag.",
        )

    worst = "read"
    any_sensitive = False
    reasons_ask = []
    inspected_invocations = 0

    # Scan units: the command itself, every command/process-substitution body,
    # and every inline `sh -c`/`bash -c` script, so an aws invocation hidden by
    # quoting, a $()/<()/>() substitution, or a shell -c wrapper is still seen.
    # Build the scan units transitively: the command, then the body of every
    # substitution / shell -c wrapper, then the bodies inside THOSE bodies, and
    # so on. This reaches a `bash -c '...aws...'` nested inside $(...)/<(...) or
    # a backtick, which a single non-recursive pass would miss. Bodies only ever
    # get shorter, `seen` dedupes, and the cap bounds any pathological fan-out.
    units, seen, queue = [], set(), [cmd]
    while queue and len(units) < 4096:
        u = queue.pop(0)
        if u in seen:
            continue
        seen.add(u)
        units.append(u)
        for body in list(extract_substitutions(u)) + list(extract_shell_c(u)):
            if body not in seen:
                queue.append(body)

    # AWS_PROFILE exported (or bare-assigned) in an earlier segment carries
    # forward to later invocations that name no profile of their own.
    carried = None

    for unit in units:
        # Collapse backslash-newline line continuations so a stamp on a
        # continued line stays attached to its aws verb, then split into shell
        # segments. A newline and a single '&' are separators too, so a later
        # command can never inherit an earlier command's inline stamp or
        # profile. Quoted separators may over-split; that only errs toward
        # stricter judgments.
        unit = re.sub(r"\\\r?\n", " ", unit)
        loop_depth = 0
        for seg in re.split(r"[;\r\n]|&&|\|\||\||&(?!&)", unit):
            # Loop/dispatcher detection on a quote-stripped view (classification
            # still uses the original seg). A segment that STARTS with a loop
            # keyword opens a loop body; a bare `done` closes it. Per-segment
            # scoping means a mutation OUTSIDE the loop -- after `done`, or in an
            # unrelated segment that merely says "wait for it" -- is no longer
            # swept up by the mass-mutation deny the way a whole-command flag was.
            bare = re.sub(r"'[^']*'|\"[^\"]*\"", " ", seg)
            # A loop head is a segment beginning with for/while/until (an inner
            # loop begins `do for ...`); `done` is a reserved word only in
            # command position, i.e. at the start of a segment, so matching it
            # there ignores a prose "done" that is merely an argument.
            if re.match(r"\s*(?:do\s+)?(?:for|while|until)\b", bare):
                loop_depth += 1
            closes_loop = bool(re.match(r"\s*done\b", bare))
            # This segment runs a mutating aws many times: it is inside a loop
            # body, or it dispatches aws over a list (xargs / find -exec /
            # parallel). The dispatcher must be followed by aws in the segment,
            # so an ordinary path or name containing "-exec"/"xargs" (e.g.
            # s3://my-exec/file) is not mistaken for a dispatch.
            seg_mass = loop_depth > 0 or bool(
                re.search(
                    r"(?:\bxargs\b|\bparallel\b|-exec(?:dir)?\b)[^\n]*\baws\b", bare
                )
            )
            tokens = tokenize(seg)
            # Detect the aws executable from the TOKENS (after the shell strips
            # quotes), not the raw string, so "aws"/'aws'/a"w"s are recognized.
            if not any(is_aws_token(tok) for tok in tokens):
                carried = update_carried_profile(tokens, carried)
                if closes_loop and loop_depth > 0:
                    loop_depth -= 1
                continue
            direct_index = command_word_index(tokens)
            for idx, tok in enumerate(tokens):
                # The executable is the aws CLI when the token is `aws` or a
                # filesystem path ending in /aws (./aws, /usr/bin/aws). A URI
                # that merely ends in /aws (s3://.../aws) is not an invocation.
                if not is_aws_token(tok):
                    continue
                if CODEX_READ_ONLY and idx != direct_index:
                    direct_token = (
                        tokens[direct_index] if direct_index is not None else ""
                    )
                    # A second aws-looking token after a real direct invocation
                    # is an argument. For other commands it is normally data;
                    # only known execution wrappers are blocked here.
                    if is_aws_token(direct_token):
                        continue
                    if codex_wrapped_text_command(tokens, direct_index):
                        continue
                    if codex_execution_wrapper(direct_token):
                        decision(
                            "deny",
                            "Blocked fail-closed: wrappers, dispatchers, and indirect "
                            "execution around the Codex AWS CLI are not allowed.",
                        )
                    continue
                if CODEX_READ_ONLY:
                    prefix_error = codex_prefix_assignment_error(tokens, idx)
                    if prefix_error:
                        decision("deny", f"Blocked fail-closed: {prefix_error}.")
                inspected_invocations += 1
                n_reasons_before = len(reasons_ask)
                service, op, profile, stamp = parse_invocation(tokens, idx)
                cls, sens = classify_op(service, op, inventory)

                # Flag escalations local to this segment
                if (
                    service == "s3"
                    and op == "sync"
                    and guarded_operation_flag(tokens, "--delete", "--del")
                ):
                    cls, sens = "destroy", True
                if guarded_operation_flag(tokens, "--force", "--for") and cls in (
                    "modify",
                    "destroy",
                ):
                    sens = True
                if re.search(
                    r"--acl[=\s]\s*[\"']?"
                    r"(?:public-read|public-read-write|authenticated-read)\b",
                    seg,
                ):
                    sens = True
                if guarded_operation_flag(
                    tokens, "--with-decryption", "--with-d"
                ) and not guarded_operation_flag(
                    tokens, "--no-with-decryption", "--no-with-d"
                ):
                    sens = True

                mutating = cls != "read"

                # A destructive verb reached with --recursive (or a wildcard
                # --include/--exclude on an s3 delete) is a MASS operation, not a
                # single target -- the confirmation prompt must say so rather than
                # repeat the single-target "look before you delete" line.
                if cls == "destroy" and (
                    guarded_operation_flag(tokens, "--recursive", "--rec")
                    or (
                        service == "s3"
                        and re.search(r"--(?:include|exclude)[=\s]", seg)
                    )
                ):
                    reasons_ask.append(
                        f"'aws {service} {op}' with --recursive/wildcard removes MANY objects, "
                        "not one target: enumerate first (bounded read), confirm the list, then "
                        "delete one target per command."
                    )

                # Grants to public principal groups open world access without
                # touching the --acl shorthand: an exposure boundary.
                if mutating and PUBLIC_GRANT.search(seg):
                    sens = True
                    reasons_ask.append(
                        f"'aws {service} {op}' grants access to a public principal group "
                        "(AllUsers/AuthenticatedUsers): confirm this exposure is intended."
                    )

                # A policy body sourced from a file can grant Principal "*";
                # the gate cannot read the file, so the operator confirms.
                if mutating and POLICY_FILE.search(seg):
                    sens = True
                    reasons_ask.append(
                        f"'aws {service} {op}' sources a policy body from a file the gate "
                        "cannot inspect: confirm it grants no public or wildcard principal."
                    )

                # Skeleton input hides the real parameters from the gate.
                if mutating and CLI_INPUT_FILE.search(seg):
                    reasons_ask.append(
                        f"'aws {service} {op}' sources its parameters from a file the gate "
                        "cannot inspect (--cli-input-json/yaml file://...): confirm the "
                        "file's contents match your stated intent."
                    )

                effective_profile = profile or carried
                prof_class = profiles.get(effective_profile or "", None)
                # The personal exemption requires an explicit profile on the
                # invocation; a carried profile only ever adds strictness.
                explicit_personal = profiles.get(profile or "", None) == "personal"

                rec = ledger_record(
                    service, op, cls, sens, stamp, effective_profile, prof_class
                )

                if (
                    service == "logs"
                    and op == "tail"
                    and guarded_operation_flag(tokens, "--follow", "--fol")
                ):
                    decision(
                        "deny",
                        "Unbounded 'aws logs tail --follow' streams are disabled. "
                        "Use a finite time window or a bounded paginated logs query.",
                        rec,
                    )

                if CODEX_READ_ONLY and service == "s3" and op == "ls":
                    decision(
                        "deny",
                        "'aws s3 ls' cannot enforce a total item bound. Use a pointed "
                        "'aws s3api list-*' operation with matching --max-items and "
                        "--page-size values instead.",
                        rec,
                    )

                if CODEX_READ_ONLY and service == "logs" and op == "tail":
                    decision(
                        "deny",
                        "'aws logs tail' cannot enforce a total event bound. Use "
                        "'aws logs filter-log-events' with matching --max-items and "
                        "--page-size values instead.",
                        rec,
                    )

                if CODEX_READ_ONLY:
                    if any(codex_abbreviated_guard_flag(token) for token in tokens):
                        decision(
                            "deny",
                            "Codex AWS reads require exact invariant flag names; "
                            "argparse-style abbreviations are not allowed.",
                            rec,
                        )
                    if tok != TRUSTED_AWS_CLI:
                        decision(
                            "deny",
                            "Codex AWS reads must invoke the trusted CLI by its exact "
                            f"path: {TRUSTED_AWS_CLI}.",
                            rec,
                        )
                    if service == "configure":
                        decision(
                            "deny",
                            "'aws configure' is disabled in the Codex read-only lane; "
                            "it can expose or change credential configuration.",
                            rec,
                        )
                    known_operation = (service, op) in inventory or op in (
                        "help",
                        "wait",
                    )
                    if not known_operation:
                        decision(
                            "deny",
                            f"'aws {service} {op}' is absent from the pinned operation "
                            "inventory and cannot run in the Codex read-only lane.",
                            rec,
                        )
                    if cls != "read":
                        decision(
                            "deny",
                            f"Codex AWS mode is read-only: 'aws {service} {op}' is "
                            f"classified as {cls}. Plan the change, but do not execute it.",
                            rec,
                        )
                    if sens:
                        decision(
                            "deny",
                            f"'aws {service} {op}' is a sensitive read and may return "
                            "credentials, secrets, or privileged material; it is disabled.",
                            rec,
                        )

                    explicit_profile = explicit_flag_value(tokens, idx, "--profile")
                    if not codex_literal_flag_value(explicit_profile):
                        decision(
                            "deny",
                            "Codex AWS reads require a literal, non-empty --profile "
                            "on every invocation.",
                            rec,
                        )
                    if profiles.get(explicit_profile) != "readonly":
                        decision(
                            "deny",
                            f"Profile '{explicit_profile}' is not classified readonly in "
                            "the private policy. Admin, frozen, personal, and unknown "
                            "profiles are blocked.",
                            rec,
                        )
                    region = explicit_flag_value(tokens, idx, "--region")
                    if not codex_literal_flag_value(region) or not re.fullmatch(
                        r"[a-z0-9][a-z0-9-]*", region
                    ):
                        decision(
                            "deny",
                            "Codex AWS reads require a literal, non-empty --region "
                            "on every invocation.",
                            rec,
                        )
                    if not stamp:
                        decision(
                            "deny",
                            f"Codex AWS reads require inline {STAMP_VAR}=<operator-task> "
                            "on every invocation.",
                            rec,
                        )
                    if not CODEX_STAMP.fullmatch(stamp):
                        decision(
                            "deny",
                            "Purpose stamps must be lowercase kebab-case with no spaces "
                            "or shell expansion.",
                            rec,
                        )
                    if not inline_assignment(
                        tokens, idx, "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "true"
                    ):
                        decision(
                            "deny",
                            "Codex AWS reads require inline "
                            "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true so configured or "
                            "environment endpoints cannot redirect credentials.",
                            rec,
                        )
                    if any(codex_forbidden_global_flag(token) for token in tokens):
                        decision(
                            "deny",
                            "Custom endpoints, CA bundles, disabled TLS verification, "
                            "and abbreviations of those flags are not allowed in the "
                            "Codex AWS lane.",
                            rec,
                        )
                    for timeout_flag in (
                        "--cli-read-timeout",
                        "--cli-connect-timeout",
                    ):
                        if not any(
                            canonical_aws_global_flag(token) == timeout_flag
                            for token in tokens
                        ):
                            continue
                        timeout_value = explicit_flag_value(tokens, idx, timeout_flag)
                        if (
                            not timeout_value
                            or not timeout_value.isdigit()
                            or not 1 <= int(timeout_value) <= MAX_CODEX_TIMEOUT_SECONDS
                        ):
                            decision(
                                "deny",
                                "Codex AWS CLI timeouts must be literal integers between "
                                f"1 and {MAX_CODEX_TIMEOUT_SECONDS} seconds.",
                                rec,
                            )
                    if "--no-cli-pager" not in tokens:
                        decision(
                            "deny",
                            "Codex AWS reads require --no-cli-pager for deterministic, "
                            "non-interactive output.",
                            rec,
                        )
                    if "--no-cli-auto-prompt" not in tokens:
                        decision(
                            "deny",
                            "Codex AWS reads require --no-cli-auto-prompt so local "
                            "AWS config cannot turn a read into an interactive prompt.",
                            rec,
                        )
                    meta = inventory.get((service, op))
                    paginated = bool(meta and len(meta) >= 3 and meta[2])
                    if paginated:
                        max_items = explicit_flag_value(tokens, idx, "--max-items")
                        if not max_items or not re.fullmatch(r"[0-9]+", max_items):
                            decision(
                                "deny",
                                "Paginated Codex AWS reads require an explicit numeric "
                                f"--max-items between 1 and {MAX_CODEX_PAGE_ITEMS}.",
                                rec,
                            )
                        if not (1 <= int(max_items) <= MAX_CODEX_PAGE_ITEMS):
                            decision(
                                "deny",
                                "Paginated Codex AWS reads require --max-items between "
                                f"1 and {MAX_CODEX_PAGE_ITEMS}.",
                                rec,
                            )
                        page_size = explicit_flag_value(tokens, idx, "--page-size")
                        if not page_size or not re.fullmatch(r"[0-9]+", page_size):
                            decision(
                                "deny",
                                "Paginated Codex AWS reads require an explicit numeric "
                                "--page-size equal to --max-items.",
                                rec,
                            )
                        if page_size != max_items:
                            decision(
                                "deny",
                                "Paginated Codex AWS reads require --page-size and "
                                "--max-items to use the same bounded value.",
                                rec,
                            )

                frozen = prof_class == "frozen" or (
                    effective_profile and effective_profile in frozen_names
                )
                if frozen and cls != "read":
                    decision(
                        "deny",
                        f"Profile '{effective_profile}' is FROZEN by local policy: reads only. "
                        f"'aws {service} {op}' is class {cls}. No mutation is permitted on this account.",
                        rec,
                    )

                if mutating and not explicit_personal:
                    if seg_mass:
                        decision(
                            "deny",
                            f"Mutating operation 'aws {service} {op}' inside a loop/batch "
                            "construct (for/while/until, xargs, find -exec, or parallel). "
                            "One target per command: enumerate first (bounded read), then issue one "
                            "explained command per resource.",
                            rec,
                        )
                    if not stamp:
                        decision(
                            "deny",
                            f"Mutating operation 'aws {service} {op}' without an inline purpose stamp. "
                            f'Re-run as: {STAMP_VAR}="{stamp_prefix or "xx"}-<task-slug>" aws ... '
                            "(stamp every aws invocation in the chain; see the aws-secure-ops skill).",
                            rec,
                        )
                if stamp:
                    if len(stamp) > MAX_STAMP_LEN:
                        decision(
                            "deny",
                            f"Purpose stamp exceeds {MAX_STAMP_LEN} chars; use a short kebab-case task slug.",
                            rec,
                        )
                    if (
                        MARKERS.search(stamp)
                        or MARKERS.search(canon_fold(stamp))
                        or brand_marker_hit(stamp)
                    ):
                        decision(
                            "deny",
                            "Purpose stamp contains a tool/automation marker (separator-"
                            "obfuscated markers included). Audit-visible values are "
                            "attributed to the accountable human operator only.",
                            rec,
                        )
                    if stamp_prefix and not stamp.startswith(stamp_prefix + "-"):
                        decision(
                            "deny",
                            f"Purpose stamp must start with the operator prefix '{stamp_prefix}-' per local policy.",
                            rec,
                        )

                # Markers inside tag values (audit-visible)
                for m in re.finditer(
                    r"--(?:tags|tag-specifications|tagging)[=\s]\s*"
                    r"((?:\"[^\"]*\"|'[^']*'|\S)+)",
                    seg,
                ):
                    tagval = m.group(1)
                    if (
                        MARKERS.search(tagval)
                        or MARKERS.search(canon_fold(tagval))
                        or brand_marker_hit(tagval)
                    ):
                        decision(
                            "deny",
                            "Tag values contain a tool/automation marker (separator- or "
                            "invisible-character-obfuscated markers included). Tags are "
                            "attributed to the accountable human operator only.",
                            rec,
                        )

                # Markers inside a resource NAME the operator is assigning on a
                # create (hard prohibition #7: audit-visible values name the
                # accountable human, never the tooling). Scoped to create so a
                # command that merely REFERENCES a pre-existing brand-named
                # resource is not blocked.
                if cls == "create":
                    for nm in name_flag_values(tokens, idx):
                        if (
                            MARKERS.search(nm)
                            or MARKERS.search(canon_fold(nm))
                            or brand_marker_hit(nm)
                        ):
                            decision(
                                "deny",
                                "Resource name contains a tool/automation marker "
                                "(separator-, invisible-, or homoglyph-obfuscated markers "
                                "included). Resource names are attributed to the accountable "
                                "human operator only.",
                                rec,
                            )

                endpoint_url = explicit_flag_value(tokens, idx, "--endpoint-url")
                if endpoint_url:
                    url = endpoint_url.strip("'\"")
                    host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]
                    if not (
                        host.endswith(".amazonaws.com")
                        or host.endswith(".amazonaws.com.cn")
                        or host in ("localhost", "127.0.0.1", "::1")
                    ):
                        reasons_ask.append(
                            f"Custom endpoint '{host}' is outside AWS: confirm this is intentional "
                            "(non-AWS endpoints are a credential-exfiltration pattern)."
                        )

                if (
                    cls == "create"
                    and required_tags
                    and not re.search(r"--(tags|tag-specifications|tagging)\b", seg)
                ):
                    reasons_ask.append(
                        f"'aws {service} {op}' creates a resource without tags; required tags exist "
                        "(environment/team/owner/purpose). Add them, or confirm this API takes none."
                    )

                if CLASS_RANK.get(cls, 2) > CLASS_RANK.get(worst, 0):
                    worst = cls
                if sens:
                    any_sensitive = True
                    if cls == "read":
                        reasons_ask.append(
                            f"'aws {service} {op}' returns credential/secret material: pipe it directly "
                            "to the consumer, never into a transcript or log."
                        )

                if len(reasons_ask) > n_reasons_before:
                    rec["_asked"] = True

            carried = update_carried_profile(tokens, carried)
            if closes_loop and loop_depth > 0:
                loop_depth -= 1

    if CODEX_READ_ONLY and inspected_invocations == 0:
        if codex_dynamic or codex_indirect_aws_wrapper(cmd):
            decision(
                "deny",
                "Blocked fail-closed: an indirect or shell-generated AWS CLI "
                "invocation is not allowed. Use the trusted path directly.",
            )
        ledger_flush()
        sys.exit(0)

    if worst == "destroy":
        reasons_ask.insert(
            0,
            "Destructive operation: confirm the single target was described first "
            "(look-before-delete) and is the intended resource.",
        )
    elif any_sensitive and worst != "read":
        reasons_ask.insert(
            0,
            "Sensitive operation (trust/exposure boundary, spend, or disruption): "
            "confirm it is authorized.",
        )

    if reasons_ask:
        for rec in _LEDGER:
            if (
                rec.get("_asked")
                or rec.get("class") == "destroy"
                or (rec.get("sensitive") and rec.get("class") != "read")
            ):
                rec["decision"] = "ask"
        decision("ask", " | ".join(dict.fromkeys(reasons_ask)))
    ledger_flush()
    sys.exit(0)


if __name__ == "__main__":
    main()
