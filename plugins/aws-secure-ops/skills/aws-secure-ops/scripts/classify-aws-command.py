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
     backticks), process substitution (<(...) / >(...)), and inline shell
     wrappers (bash -c / sh -c '<script>') are extracted and classified like
     any other invocation, so a mutation cannot hide inside a quoted argument,
     a process substitution, or a -c script string.
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

Documented residual: if the policy file is missing or corrupt the gate still
runs (fail-open on configuration, as designed), but the frozen-by-name check
cannot fire because no profile is classified. The stamp rule still denies
unstamped mutations regardless. Account names stay in the private policy
file; they are never hardcoded in this shareable gate.

Local decision ledger: the gate appends one JSON line per inspected aws
invocation (allow, ask, and deny alike) to AWS_OPS_LEDGER_FILE if set, else
~/.claude/aws-ops-ledger.jsonl. Disabled when the policy file has
"ledger": false. Only classification metadata is written — never raw command
text, argument values, tag values, or secret material. Ledger I/O is
best-effort: a failure never raises, delays, or changes the gate decision.

Configuration (optional, binding when present):
  ~/.claude/aws-ops.policy.json     override path: AWS_OPS_POLICY_FILE
  {
    "operator": {"name": "...", "stamp_prefix": "xx"},
    "profiles": {"prof-name": "readonly|admin|frozen|personal", ...},
    "required_tags": {"key": "value", ...},
    "ledger": true
  }

The gate is a seatbelt, not the judgment: it fails open for commands it cannot
parse as aws invocations, and fails conservative for operations it cannot
classify.
"""

import csv
import json
import os
import re
import sys
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

STAMP_VAR = "AWS_SDK_UA_APP_ID"
MAX_STAMP_LEN = 50

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
POLICY_FILE = re.compile(r"--(?:[a-z]+-)*policy(?:-document)?[= ]\s*[\"']?file://")

# Skeleton parameters sourced from a file the gate cannot read.
CLI_INPUT_FILE = re.compile(r"--cli-input-(?:json|yaml)[= ]\s*[\"']?file://")

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
        with open(_LEDGER_PATH, "a", encoding="utf-8") as fh:
            for rec in _LEDGER:
                fh.write(json.dumps({k: rec.get(k) for k in LEDGER_KEYS}) + "\n")
    except Exception:
        pass


def decision(action, reason, rec=None):
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


def load_inventory():
    inv = (
        Path(__file__).resolve().parent.parent
        / "references"
        / "inventory"
        / "inventory.csv"
    )
    table = {}
    try:
        with inv.open(newline="", encoding="utf-8") as fh:
            for row in csv.reader(fh):
                if len(row) >= 4 and row[0] != "service":
                    table[(row[0], row[1])] = (row[2], row[3] == "1")
    except OSError:
        pass
    return table


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
            flag = t.split("=", 1)[0]
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
    op = words[1] if len(words) > 1 else "help"
    if service in (None, "--version", "-v"):
        service, op = "help", "help"
    return service, op, profile, stamp


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


def brand_marker_hit(value):
    """Second marker pass: canonicalize (NFKC + homoglyph fold), strip
    separators, then look for high-signal brand tokens only, so xx-c-l-a-u-d-e-run,
    a soft-hyphen variant, and a Cyrillic-lookalike cannot dodge the
    word-boundary pass while ordinary words (claudia, geminide-...) stay clean."""
    stripped = re.sub(r"[-_.\s]", "", canon_fold(value))
    return any(tok in stripped for tok in BRAND_TOKENS)


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
                if t.startswith("-"):
                    # A short-option cluster carrying 'c' (e.g. -c, -lc) means
                    # the next positional is the script. Long options handled
                    # above, so a bare '-'-prefixed token here is short-form.
                    if "c" in t:
                        saw_c = True
                    j += 1
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


def main():
    global _LEDGER_ENABLED
    try:
        event = json.load(sys.stdin)
    except ValueError:
        sys.exit(0)
    if event.get("tool_name") != "Bash":
        sys.exit(0)
    cmd = (event.get("tool_input") or {}).get("command") or ""
    # Pre-filter: skip the full parse only when there is no aws token at all.
    # The preceding-char class includes quotes so an aws call wrapped in
    # `bash -c 'aws ...'` still reaches the parser (extract_shell_c). Being
    # broader here only ever means more commands are fully parsed, never fewer.
    if not re.search(r"(^|[\s;&|(`{'\"])(?:\S*/)?aws(\s|$)", cmd):
        sys.exit(0)

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

    if re.search(r"--no-verify-ssl\b", cmd):
        decision(
            "deny",
            "TLS verification must never be disabled (--no-verify-ssl). Remove the flag.",
        )

    worst = "read"
    any_sensitive = False
    reasons_ask = []

    loop_head = re.compile(r"(^|[;&|]\s*|\$\(\s*|`\s*)\s*(for|while|until)\s")
    has_loop = (
        bool(loop_head.search(cmd))
        or bool(re.search(r"\bxargs\b[^;|&]*\baws\b", cmd))
        or bool(re.search(r"-exec(?:dir)?\b[^;|&]*\baws\b", cmd))
        or bool(re.search(r"\bparallel\b[^;|&]*\baws\b", cmd))
    )

    # Scan units: the command itself, every command/process-substitution body,
    # and every inline `sh -c`/`bash -c` script, so an aws invocation hidden by
    # quoting, a $()/<()/>() substitution, or a shell -c wrapper is still seen.
    # Build the scan units transitively: the command, then the body of every
    # substitution / shell -c wrapper, then the bodies inside THOSE bodies, and
    # so on. This reaches a `bash -c '...aws...'` nested inside $(...)/<(...) or
    # a backtick, which a single non-recursive pass would miss. Bodies only ever
    # get shorter, `seen` dedupes, and the cap bounds any pathological fan-out.
    units, seen, queue = [], set(), [cmd]
    while queue and len(units) < 256:
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
        for seg in re.split(r"[;\r\n]|&&|\|\||\||&(?!&)", unit):
            tokens = tokenize(seg)
            if not re.search(r"(^|[\s(`{])(?:\S*/)?aws(\s|$)", seg):
                carried = update_carried_profile(tokens, carried)
                continue
            for idx, tok in enumerate(tokens):
                # The executable is the aws CLI when the token is `aws` or a
                # filesystem path ending in /aws (./aws, /usr/bin/aws). A URI
                # that merely ends in /aws (s3://.../aws) is not an invocation.
                if not (tok == "aws" or (tok.endswith("/aws") and "://" not in tok)):
                    continue
                n_reasons_before = len(reasons_ask)
                service, op, profile, stamp = parse_invocation(tokens, idx)
                cls, sens = classify_op(service, op, inventory)

                # Flag escalations local to this segment
                if service == "s3" and op == "sync" and "--delete" in tokens:
                    cls, sens = "destroy", True
                if re.search(r"--force\b", seg) and cls in ("modify", "destroy"):
                    sens = True
                if re.search(
                    r"--acl[=\s]\s*[\"']?"
                    r"(?:public-read|public-read-write|authenticated-read)\b",
                    seg,
                ):
                    sens = True
                if (
                    re.search(r"--with-decryption\b", seg)
                    and "--no-with-decryption" not in seg
                ):
                    sens = True

                mutating = cls != "read"

                # A destructive verb reached with --recursive (or a wildcard
                # --include/--exclude on an s3 delete) is a MASS operation, not a
                # single target -- the confirmation prompt must say so rather than
                # repeat the single-target "look before you delete" line.
                if cls == "destroy" and (
                    re.search(r"--recursive\b", seg)
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
                    if has_loop:
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
                    r"--(?:tags|tag-specifications|tagging)[= ]((?:\"[^\"]*\"|'[^']*'|\S)+)",
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

                m = re.search(r"--endpoint-url[= ](\S+)", seg)
                if m:
                    url = m.group(1).strip("'\"")
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
