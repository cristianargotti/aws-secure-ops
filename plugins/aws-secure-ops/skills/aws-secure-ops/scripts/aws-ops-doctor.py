#!/usr/bin/env python3
"""Installation self-test ("doctor") for the aws-secure-ops skill.

Verifies that the whole safety apparatus is healthy on this machine:
the classification gate compiles, the operation inventory is intact, the
gate is actually registered as a live PreToolUse hook, the local policy
file (if any) is schema-sane, the offline unit suites pass, and the
stamp seatbelt really denies an unstamped mutation while letting a
pointed read through.

Everything runs offline. The gate is only exercised through the same
JSON hook-event envelope the agent harness uses; no aws command is ever
executed and no network call is made.

Usage:
    python3 scripts/aws-ops-doctor.py            # full run (all checks)
    python3 scripts/aws-ops-doctor.py --quick    # skip the slow *.sh suites
    python3 scripts/aws-ops-doctor.py --session   # watchdog for a SessionStart hook

Modes:
    (default)  Every check, including the offline unit suites. Exit status
               is nonzero when any check FAILs. WARNs (missing optional
               policy file, inventory drift, misleading profile names) do
               not fail the run but deserve a look.
    --quick    Every check EXCEPT executing the test-*.sh suites (the slow
               part). Keeps the live seatbelt probe. Targets well under a
               second so it is cheap to run often.
    --session  Implies --quick and is meant to be wired as a SessionStart
               hook. Reads and ignores the JSON on stdin. On success it
               prints NOTHING and exits 0. On any failure -- a failed check
               or a loose seatbelt -- it prints exactly one JSON object,
               {"systemMessage": "aws-secure-ops watchdog: <problem>"}, and
               still exits 0: a watchdog must never block the session.

Environment overrides (all optional; conservative real defaults):
    AWS_OPS_GATE_FILE     path to the classification gate to probe
    AWS_OPS_LEDGER_FILE   path to the decision ledger (for rotation)
    HOME                  resolves settings.json / policy / plugin state
"""

import csv
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = SKILL_ROOT / "scripts"


def _gate_path():
    """The classification gate the doctor probes.

    Defaults to the frozen gate shipped beside this script. The env
    override exists only so a sandboxed test can point the doctor at a
    broken/missing gate and confirm the seatbelt checks fail closed; it
    never changes the real hook wiring.
    """
    env = os.environ.get("AWS_OPS_GATE_FILE")
    return Path(env).expanduser() if env else SCRIPTS / "classify-aws-command.py"


GATE = _gate_path()
INVENTORY_CSV = SKILL_ROOT / "references" / "inventory" / "inventory.csv"
SUMMARY_JSON = SKILL_ROOT / "references" / "inventory" / "summary.json"
SETTINGS_JSON = Path.home() / ".claude" / "settings.json"
POLICY_JSON = Path.home() / ".claude" / "aws-ops.policy.json"
PLUGINS_INSTALLED = Path.home() / ".claude" / "plugins" / "installed_plugins.json"
# The plugin id the gate ships under, matched by prefix so any marketplace
# suffix ("aws-secure-ops@<marketplace>") counts.
PLUGIN_ID_PREFIX = "aws-secure-ops@"
LEDGER_ROTATE_THRESHOLD = 5 * 1024 * 1024  # ~5 MB


def _ledger_path():
    env = os.environ.get("AWS_OPS_LEDGER_FILE")
    return (
        Path(env).expanduser()
        if env
        else Path.home() / ".claude" / "aws-ops-ledger.jsonl"
    )


EXPECTED_CSV_HEADER = [
    "service",
    "operation",
    "class",
    "sensitive",
    "dryrun",
    "paginated",
    "source",
    "rule",
]
INVENTORY_DRIFT_TOLERANCE = 0.02  # 2% row drift is "roughly matches"
SUBPROCESS_TIMEOUT = 120  # seconds; generous for the unit suites

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"

results = []  # list of (status, name, reason)

# When true (session/watchdog mode) checks record silently; the caller
# decides what, if anything, to emit. A watchdog stays quiet on success.
QUIET = False


def record(status, name, reason):
    results.append((status, name, reason))
    if not QUIET:
        print(f"{status:4}  {name}: {reason}")


def check(name):
    """Decorator: run the check, and convert any exception into a FAIL.

    A check function returns (status, reason). Anything it cannot read,
    parse, or execute must surface as a FAIL with a message, never as a
    silent skip: an invisible failure in a safety net is worse than an
    honest one.
    """

    def wrap(fn):
        def run():
            try:
                status, reason = fn()
            except Exception as exc:  # fail closed
                status, reason = FAIL, f"check raised {type(exc).__name__}: {exc}"
            record(status, name, reason)

        return run

    return wrap


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


@check("python3 interpreter")
def check_python():
    v = sys.version_info
    if v < (3, 8):
        return FAIL, f"python {v.major}.{v.minor}.{v.micro} is too old (need 3.8+)"
    return PASS, f"python {v.major}.{v.minor}.{v.micro} at {sys.executable}"


@check("gate script compiles")
def check_gate_compiles():
    if not GATE.is_file():
        return FAIL, f"gate not found at {GATE}"
    source = GATE.read_text(encoding="utf-8")
    # Compile only: proves the file is valid Python without executing it
    # (and therefore without touching AWS or the live hook path).
    compile(source, str(GATE), "exec")
    return PASS, f"{GATE.name} is valid Python ({len(source.splitlines())} lines)"


@check("inventory csv")
def check_inventory():
    if not INVENTORY_CSV.is_file():
        return FAIL, f"missing {INVENTORY_CSV}"
    with INVENTORY_CSV.open(newline="", encoding="utf-8") as fh:
        reader = csv.reader(fh)
        try:
            header = next(reader)
        except StopIteration:
            return FAIL, "inventory.csv is empty"
        if header != EXPECTED_CSV_HEADER:
            return FAIL, f"unexpected header {header!r}"
        rows = sum(1 for _ in reader)
    if rows == 0:
        return FAIL, "inventory.csv has a header but no data rows"

    if not SUMMARY_JSON.is_file():
        return (
            WARN,
            f"{rows} rows, but {SUMMARY_JSON.name} is missing so the count is unverified",
        )
    summary = json.loads(SUMMARY_JSON.read_text(encoding="utf-8"))
    expected = summary.get("operations")
    if not isinstance(expected, int) or expected <= 0:
        return WARN, f"{rows} rows, but summary.json has no usable 'operations' count"
    drift = abs(rows - expected) / expected
    if drift > INVENTORY_DRIFT_TOLERANCE:
        return WARN, (
            f"{rows} rows vs {expected} in summary.json "
            f"({drift:.1%} drift) — inventory may need a rebuild"
        )
    return PASS, f"{rows} rows, header ok, matches summary.json ({expected})"


@check("inventory verifier")
def check_inventory_verifier():
    verifier = SCRIPTS / "verify-inventory.py"
    if not verifier.is_file():
        return (
            PASS,
            "verify-inventory.py not present (optional); csv check above stands alone",
        )
    proc = subprocess.run(
        [sys.executable, str(verifier)],
        capture_output=True,
        text=True,
        timeout=SUBPROCESS_TIMEOUT,
    )
    tail = (proc.stdout + proc.stderr).strip().splitlines()
    last = tail[-1] if tail else "(no output)"
    if proc.returncode != 0:
        return FAIL, f"verify-inventory.py exited {proc.returncode}: {last}"
    return PASS, f"verify-inventory.py exited 0: {last}"


def _read_settings():
    """(settings_dict_or_None, error_or_None). Missing file is not an error."""
    if not SETTINGS_JSON.is_file():
        return None, None
    try:
        return json.loads(SETTINGS_JSON.read_text(encoding="utf-8")), None
    except (json.JSONDecodeError, OSError) as exc:
        return None, f"settings.json unreadable: {exc}"


def _manual_hook_present(settings):
    """True if settings.json wires a PreToolUse Bash hook to the gate."""
    if not isinstance(settings, dict):
        return False
    entries = settings.get("hooks", {}).get("PreToolUse", [])
    if not isinstance(entries, list):
        return False
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        matcher = entry.get("matcher", "")
        # The matcher is a regex; it must catch the Bash tool.
        try:
            matches_bash = bool(re.fullmatch(matcher, "Bash")) or matcher == "Bash"
        except re.error:
            matches_bash = matcher == "Bash"
        if not matches_bash:
            continue
        for hook in entry.get("hooks", []):
            if (
                isinstance(hook, dict)
                and hook.get("type") == "command"
                and "classify-aws-command.py" in str(hook.get("command", ""))
            ):
                return True
    return False


def _plugin_gate_enabled(settings):
    """True if the aws-secure-ops plugin is installed AND enabled.

    After migration the gate is provided by the plugin rather than by a
    hand-written settings.json hook: the plugin registers the PreToolUse
    hook itself. We treat that wiring as equivalent. Installed is read
    from installed_plugins.json; enabled from the enabledPlugins map in
    settings.json. Both must be true, matched by the "aws-secure-ops@"
    prefix so any marketplace suffix counts.
    """
    installed = False
    if PLUGINS_INSTALLED.is_file():
        try:
            data = json.loads(PLUGINS_INSTALLED.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            data = None
        if isinstance(data, dict):
            plugins = data.get("plugins", {})
            if isinstance(plugins, dict):
                installed = any(
                    isinstance(k, str) and k.startswith(PLUGIN_ID_PREFIX)
                    for k in plugins
                )
    enabled = False
    if isinstance(settings, dict):
        enabled_map = settings.get("enabledPlugins", {})
        if isinstance(enabled_map, dict):
            enabled = any(
                isinstance(k, str) and k.startswith(PLUGIN_ID_PREFIX) and v is True
                for k, v in enabled_map.items()
            )
    return installed and enabled


@check("gate registered as PreToolUse hook")
def check_hook_registration():
    settings, err = _read_settings()

    if _manual_hook_present(settings):
        return (
            PASS,
            "PreToolUse Bash hook in settings.json points at classify-aws-command.py",
        )
    if _plugin_gate_enabled(settings):
        return PASS, (
            "aws-secure-ops plugin is installed and enabled; it provides the "
            "PreToolUse gate"
        )

    # Neither wiring present -> the seatbelt is not buckled. Fail closed.
    detail = err or (
        "no PreToolUse Bash hook running classify-aws-command.py, and the "
        "aws-secure-ops plugin is not both installed and enabled"
    )
    return FAIL, f"the gate is not wired into the agent's Bash tool: {detail}"


@check("policy file")
def check_policy():
    if not POLICY_JSON.is_file():
        return WARN, (
            f"{POLICY_JSON} absent — the gate runs on conservative "
            "defaults; a policy file tightens it to your accounts"
        )
    try:
        policy = json.loads(POLICY_JSON.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return FAIL, f"policy file is not valid JSON: {exc}"
    if not isinstance(policy, dict):
        return FAIL, "policy file top level must be a JSON object"

    problems = []
    operator = policy.get("operator")
    if not (isinstance(operator, dict) and operator.get("stamp_prefix")):
        problems.append("operator.stamp_prefix missing")
    profiles = policy.get("profiles", {})
    if not isinstance(profiles, dict):
        problems.append("profiles must be an object")
    else:
        allowed = {"readonly", "admin", "frozen", "personal"}
        bad = sorted(k for k, v in profiles.items() if v not in allowed)
        if bad:
            problems.append(f"profiles with invalid class: {', '.join(bad)}")
    if "required_tags" in policy and not isinstance(policy["required_tags"], dict):
        problems.append("required_tags must be an object")
    if problems:
        return FAIL, "; ".join(problems)
    return PASS, f"valid JSON, stamp prefix set, {len(profiles)} profile(s) classified"


# Token families for the misleading-name lint. "ro" is only ever matched as
# a whole delimited token (never a bare substring), so words like "prod" or
# "control" do not trip it.
_READONLY_SUBSTRINGS = ("readonly", "read-only", "reader")
_ADMIN_SUBSTRINGS = ("admin", "administrator")


def _has_readonly_hint(name: str) -> bool:
    lower = name.lower()
    if any(s in lower for s in _READONLY_SUBSTRINGS):
        return True
    tokens = re.split(r"[^a-z0-9]+", lower)
    return "ro" in tokens


def _has_admin_hint(name: str) -> bool:
    # "administrator" contains "admin", so one substring covers both.
    return "admin" in name.lower()


def _load_policy_with_dupes():
    """Return (policy, duplicate_profile_names, error).

    json.load silently collapses duplicate object keys, so we re-parse with
    an object_pairs_hook to surface repeated profile entries -- a real
    misconfiguration that the plain parse would hide.
    """
    dupes = []

    def hook(pairs):
        seen = set()
        local_dupes = []
        for k, _ in pairs:
            if k in seen:
                local_dupes.append(k)
            seen.add(k)
        if local_dupes:
            dupes.append((frozenset(k for k, _ in pairs), local_dupes))
        return dict(pairs)

    try:
        text = POLICY_JSON.read_text(encoding="utf-8")
    except OSError as exc:
        return None, [], f"cannot read policy file: {exc}"
    try:
        policy = json.loads(text, object_pairs_hook=hook)
    except json.JSONDecodeError as exc:
        return None, [], f"policy file is not valid JSON: {exc}"
    if not isinstance(policy, dict):
        return None, [], "policy file top level must be a JSON object"

    profiles = policy.get("profiles", {})
    profile_names = set(profiles) if isinstance(profiles, dict) else set()
    # Attribute duplicates to the profiles object when their sibling keys are
    # profile names; otherwise report them generically.
    dup_profiles = []
    for keyset, local in dupes:
        if profile_names and keyset & profile_names:
            dup_profiles.extend(local)
        else:
            dup_profiles.extend(local)
    return policy, sorted(set(dup_profiles)), None


@check("policy lint")
def check_policy_lint():
    """Advisory lint over the policy file. WARNs, never FAILs.

    Flags misleading profile names (a read-only-sounding name classed admin
    or vice versa), duplicate profile entries, and frozen_accounts that are
    unreachable because no profile can operate them. These are judgment
    smells, not schema violations -- the schema check above owns hard
    failures -- so the worst this returns is a WARN.
    """
    if not POLICY_JSON.is_file():
        return PASS, "no policy file present; nothing to lint (see policy file check)"

    policy, dup_profiles, err = _load_policy_with_dupes()
    if err:
        # Fail closed as a WARN: this check never escalates to FAIL, and the
        # schema check above already FAILs on unreadable/invalid policy.
        return WARN, err

    problems = []

    profiles = policy.get("profiles", {})
    if isinstance(profiles, dict):
        misleading = []
        for name, klass in profiles.items():
            if not isinstance(name, str):
                continue
            ro = _has_readonly_hint(name)
            adm = _has_admin_hint(name)
            # Only flag an unambiguous mismatch: a name that hints one family
            # while classed the other, and does NOT also hint the class it
            # actually holds (names like "adminaccess-readonly" carry both
            # hints and are left alone).
            if klass == "admin" and ro and not adm:
                misleading.append(f"{name!r} sounds read-only but is classed admin")
            elif klass == "readonly" and adm and not ro:
                misleading.append(f"{name!r} sounds admin but is classed readonly")
        if misleading:
            problems.append("misleading names: " + "; ".join(misleading))

    if dup_profiles:
        problems.append("duplicate profile entries: " + ", ".join(dup_profiles))

    frozen_accounts = policy.get("frozen_accounts")
    if isinstance(frozen_accounts, list):
        profile_names = set(profiles) if isinstance(profiles, dict) else set()
        has_frozen_profile = isinstance(profiles, dict) and any(
            v == "frozen" for v in profiles.values()
        )
        orphaned = []
        for acct in frozen_accounts:
            if not isinstance(acct, (str, int)):
                continue
            acct_s = str(acct)
            # An entry is "matched" if it names a known profile, or it is an
            # account id (all digits) reachable through a frozen-classed
            # profile. Anything else is an orphan the operator should notice.
            named = acct_s in profile_names
            reachable = acct_s.isdigit() and has_frozen_profile
            if not (named or reachable):
                orphaned.append(acct_s)
        if orphaned:
            problems.append(
                "frozen_accounts matching no profile: " + ", ".join(orphaned)
            )

    if problems:
        return WARN, "; ".join(problems)
    return PASS, "no misleading names, duplicates, or orphaned frozen_accounts"


def run_suite(script: Path):
    """Run one offline unit suite; returns (status, reason)."""
    if not os.access(script, os.R_OK):
        return FAIL, f"{script.name} exists but is not readable"
    proc = subprocess.run(
        ["bash", str(script)],
        capture_output=True,
        text=True,
        timeout=SUBPROCESS_TIMEOUT,
        cwd=str(SCRIPTS),
    )
    out = (proc.stdout + proc.stderr).strip().splitlines()
    last = out[-1] if out else "(no output)"
    if proc.returncode != 0:
        failing = [ln for ln in out if ln.startswith("FAIL")]
        detail = failing[0] if failing else last
        return FAIL, f"exited {proc.returncode}: {detail}"
    return PASS, last


@check("unit suite: test-classify-aws-command.sh")
def check_unit_suite_classify():
    script = SCRIPTS / "test-classify-aws-command.sh"
    if not script.is_file():
        return (
            FAIL,
            "test-classify-aws-command.sh is missing — the gate has no regression net",
        )
    return run_suite(script)


@check("unit suite: test-gate-hardening.sh")
def check_unit_suite_hardening():
    script = SCRIPTS / "test-gate-hardening.sh"
    if not script.is_file():
        return PASS, "not present (optional hardening suite); nothing to run"
    return run_suite(script)


def probe_gate(command: str, policy_file: str):
    """Feed one command through the gate exactly as the hook harness would.

    The command travels inside the JSON hook-event envelope on stdin; the
    gate never executes it, it only classifies it. Silent exit 0 means
    allow; otherwise the decision is in the emitted JSON.
    """
    event = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}})
    env = dict(os.environ)
    env["AWS_OPS_POLICY_FILE"] = policy_file  # isolate from any private policy
    # Never let a probe decision reach the operator's real reconciliation
    # ledger: the SessionStart watchdog runs this on every session start.
    env["AWS_OPS_LEDGER_FILE"] = os.devnull
    proc = subprocess.run(
        [sys.executable, str(GATE)],
        input=event,
        capture_output=True,
        text=True,
        timeout=SUBPROCESS_TIMEOUT,
        env=env,
    )
    out = proc.stdout.strip()
    if not out:
        return "allow", ""
    decision = json.loads(out)["hookSpecificOutput"]["permissionDecision"]
    reason = json.loads(out)["hookSpecificOutput"].get("permissionDecisionReason", "")
    return decision, reason


@check("stamp seatbelt is live")
def check_stamp_mechanism():
    if not GATE.is_file():
        return FAIL, "gate script missing; cannot probe"
    # A throwaway policy so the probe is deterministic and never reads the
    # operator's private policy file.
    probe_policy = {
        "operator": {"name": "doctor-probe", "stamp_prefix": "xx"},
        "profiles": {"probe-admin": "admin", "probe-read": "readonly"},
        "required_tags": {},
        "ledger": False,
    }
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(probe_policy, fh)
        policy_path = fh.name
    try:
        decision, _ = probe_gate(
            "aws ec2 create-tags --resources vol-0doctor "
            "--tags Key=environment,Value=example --profile probe-admin",
            policy_path,
        )
        if decision != "deny":
            return (
                FAIL,
                f"unstamped mutation was '{decision}', expected deny — the seatbelt is loose",
            )
        decision, reason = probe_gate(
            "AWS_SDK_UA_APP_ID=xx-doctor aws ec2 describe-volumes "
            "--volume-ids vol-0doctor --profile probe-read",
            policy_path,
        )
        if decision != "allow":
            return FAIL, f"pointed read was '{decision}' ({reason}), expected allow"
        return PASS, "unstamped mutation denied, pointed read allowed"
    finally:
        os.unlink(policy_path)


def maybe_rotate_ledger():
    """Best-effort: ask the ledger CLI to rotate if the file is oversized.

    The doctor is a natural, frequently-run place to keep the append-only
    ledger from growing without bound. This is strictly best effort: any
    problem -- missing CLI, unreadable file, nonzero exit -- is swallowed
    and never affects the doctor's result. The rotation decision itself is
    delegated to the ledger CLI's own threshold check.
    """
    try:
        ledger = _ledger_path()
        if not ledger.is_file():
            return
        if ledger.stat().st_size <= LEDGER_ROTATE_THRESHOLD:
            return
        ledger_cli = SCRIPTS / "aws-ops-ledger.py"
        if not ledger_cli.is_file():
            return
        subprocess.run(
            [
                sys.executable,
                str(ledger_cli),
                "rotate",
                "--if-larger-than",
                str(LEDGER_ROTATE_THRESHOLD),
            ],
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
        )
    except Exception:
        # A rotation failure must never affect the doctor result.
        pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

USAGE = """usage: aws-ops-doctor.py [--quick | --session]

  (no flag)   full run: every check, including the offline *.sh suites
  --quick     every check except the slow test-*.sh suites; keeps the
              live seatbelt probe; targets well under a second
  --session   implies --quick; SessionStart watchdog. Reads and ignores
              stdin, prints nothing on success, and on any failure prints
              one {"systemMessage": "..."} line. Always exits 0.
"""


def parse_args(argv):
    """Return (quick, session).

    Unknown flags fail closed with usage and a nonzero exit -- except in
    --session (watchdog) mode, where nothing may ever cause a nonzero exit
    or block the session, so stray args are tolerated and ignored.
    """
    args = argv[1:]
    session = "--session" in args
    quick = session
    unknown = []
    for arg in args:
        if arg == "--quick":
            quick = True
        elif arg == "--session":
            pass  # handled above
        elif arg in ("-h", "--help") and not session:
            print(USAGE, end="")
            sys.exit(0)
        else:
            unknown.append(arg)
    if unknown and not session:
        print(f"error: unknown argument(s): {', '.join(unknown)}\n", file=sys.stderr)
        print(USAGE, end="", file=sys.stderr)
        sys.exit(2)
    return quick, session


def selected_checks(quick):
    checks = [
        check_python,
        check_gate_compiles,
        check_inventory,
        check_inventory_verifier,
        check_hook_registration,
        check_policy,
        check_policy_lint,
    ]
    if not quick:
        # The *.sh suites are the slow part; --quick and --session skip them.
        checks += [check_unit_suite_classify, check_unit_suite_hardening]
    checks.append(check_stamp_mechanism)
    return checks


def _session_problem():
    """A concise one-line problem for the watchdog message.

    Prefer the seatbelt failure when present -- a loose seatbelt is the
    gravest condition -- otherwise the first failing check.
    """
    fails = [(name, reason) for status, name, reason in results if status == FAIL]
    if not fails:
        return None
    seatbelt = [f for f in fails if "seatbelt" in f[0]]
    name, reason = (seatbelt or fails)[0]
    problem = f"{name}: {reason}"
    problem = " ".join(problem.split())  # collapse whitespace/newlines
    if len(problem) > 200:
        problem = problem[:197] + "..."
    return problem


def run_session():
    """SessionStart watchdog. Never blocks: always exits 0."""
    global QUIET
    QUIET = True
    # Read and ignore whatever the harness sends on stdin.
    try:
        sys.stdin.read()
    except Exception:
        pass
    try:
        for run in selected_checks(quick=True):
            run()
        maybe_rotate_ledger()
        problem = _session_problem()
    except Exception as exc:  # a watchdog must never crash the session
        problem = f"doctor watchdog crashed: {type(exc).__name__}: {exc}"
    if problem:
        print(json.dumps({"systemMessage": f"aws-secure-ops watchdog: {problem}"}))
    sys.exit(0)


def main():
    quick, session = parse_args(sys.argv)
    if session:
        run_session()
        return  # unreachable; run_session exits

    print(f"aws-secure-ops doctor — skill root: {SKILL_ROOT}")
    if quick:
        print("(quick mode: skipping the test-*.sh suites)")
    print()

    for run in selected_checks(quick):
        run()

    maybe_rotate_ledger()

    counts = {PASS: 0, WARN: 0, FAIL: 0}
    for status, _, _ in results:
        counts[status] += 1
    print(f"\nSummary: {counts[PASS]} pass, {counts[WARN]} warn, {counts[FAIL]} fail")
    if counts[FAIL]:
        print(
            "The safety apparatus is NOT fully healthy; fix the failures before "
            "trusting the gate."
        )
        sys.exit(1)
    if counts[WARN]:
        print("Healthy with caveats — review the warnings above.")
    else:
        print("All checks passed; the seatbelt is buckled.")
    sys.exit(0)


if __name__ == "__main__":
    main()
