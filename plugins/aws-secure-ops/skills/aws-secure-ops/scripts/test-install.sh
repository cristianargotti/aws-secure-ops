#!/usr/bin/env bash
# Sandboxed tests for aws-ops-install.py. Everything happens inside a throwaway
# HOME (and throwaway shell rc): the real ~/.claude is never read or written.
# Fully offline. Exit 0 when every assertion passes.
#
# Covered:
#   * install merges the gate hook and backs the settings file up first
#   * a second install is a true no-op (no duplicate hook entry)
#   * an unrelated pre-existing hook survives install and uninstall
#   * --uninstall removes only our entry, leaving the unrelated one
#   * the policy file is scaffolded when absent and never clobbered when present
#   * a fresh install with no prior settings still wires the gate
#   * --with-shim appends an idempotent source line; --purge reverts policy+shim
#   * a corrupt settings file fails closed (nonzero exit, file untouched)

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
INSTALL="$HERE/aws-ops-install.py"
GATE="$HERE/classify-aws-command.py"

PY="$(command -v python3 || true)"
if [ -z "$PY" ]; then
  echo "FAIL  python3 not found on PATH; cannot run installer tests" >&2
  exit 1
fi

# A single sandbox HOME for the whole run. Nothing outside it is touched.
SANDBOX="$(mktemp -d 2>/dev/null || mktemp -d -t aws-ops-install)"
export HOME="$SANDBOX"
export AWS_OPS_ZSHRC="$SANDBOX/.zshrc"
# Keep the gate's ledger inside the sandbox too, just in case anything runs it.
export AWS_OPS_LEDGER_FILE="$SANDBOX/ledger.jsonl"
unset AWS_OPS_SETTINGS_FILE AWS_OPS_POLICY_FILE 2>/dev/null || true

SETTINGS="$HOME/.claude/settings.json"
POLICY="$HOME/.claude/aws-ops.policy.json"

cleanup() { rm -rf "$SANDBOX"; }
trap cleanup EXIT

pass=0
fail=0
ok()   { pass=$((pass+1)); echo "PASS  $1"; }
bad()  { fail=$((fail+1)); echo "FAIL  $1"; }

# Count how many hooks in settings.json reference our gate path.
gate_count() {
  "$PY" - "$SETTINGS" "$GATE" <<'PYEOF'
import json, sys
try:
    data = json.load(open(sys.argv[1]))
except Exception:
    print(0); sys.exit(0)
gate = sys.argv[2]
n = 0
for entry in data.get("hooks", {}).get("PreToolUse", []):
    if not isinstance(entry, dict):
        continue
    for h in entry.get("hooks", []) or []:
        if isinstance(h, dict) and gate in str(h.get("command", "")):
            n += 1
print(n)
PYEOF
}

# True (exit 0) when settings.json contains a hook whose command has $1.
has_command_substr() {
  "$PY" - "$SETTINGS" "$1" <<'PYEOF'
import json, sys
try:
    data = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(1)
needle = sys.argv[2]
for entry in data.get("hooks", {}).get("PreToolUse", []):
    if not isinstance(entry, dict):
        continue
    for h in entry.get("hooks", []) or []:
        if isinstance(h, dict) and needle in str(h.get("command", "")):
            sys.exit(0)
sys.exit(1)
PYEOF
}

count_backups() {
  ls "$HOME/.claude/settings.json.bak."* 2>/dev/null | wc -l | tr -d ' '
}

run_install() { "$PY" "$INSTALL" --no-doctor "$@" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# Case 1: install into a settings file that already carries an unrelated hook.
# ---------------------------------------------------------------------------
mkdir -p "$HOME/.claude"
cat > "$SETTINGS" <<'EOF'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "echo unrelated-guard" }
        ]
      }
    ]
  }
}
EOF

run_install
rc=$?
[ "$rc" -eq 0 ] && ok "install exits 0" || bad "install exit $rc"

[ "$(gate_count)" = "1" ] && ok "gate hook merged (count=1)" || bad "gate hook count=$(gate_count), expected 1"

if has_command_substr "echo unrelated-guard"; then
  ok "pre-existing unrelated hook survived install"
else
  bad "unrelated hook was lost during install"
fi

if [ "$(count_backups)" -ge 1 ]; then
  ok "timestamped backup created ($(count_backups))"
else
  bad "no backup was created"
fi

[ -f "$POLICY" ] && ok "policy file scaffolded when absent" || bad "policy file not scaffolded"

# ---------------------------------------------------------------------------
# Case 2: second install is a no-op — no duplicate, policy not clobbered.
# ---------------------------------------------------------------------------
# Stamp the policy so we can prove it is left alone.
"$PY" - "$POLICY" <<'PYEOF'
import json, sys
p = sys.argv[1]
d = json.load(open(p))
d["notes"] = "USER-EDITED-MARKER"
json.dump(d, open(p, "w"), indent=2)
PYEOF

backups_before="$(count_backups)"
run_install
[ "$(gate_count)" = "1" ] && ok "second install did not duplicate the hook" || bad "duplicate hook after re-install (count=$(gate_count))"

if [ "$(count_backups)" = "$backups_before" ]; then
  ok "no-op re-install wrote no new backup"
else
  bad "re-install created an unnecessary backup"
fi

marker="$("$PY" -c 'import json,sys;print(json.load(open(sys.argv[1])).get("notes",""))' "$POLICY")"
[ "$marker" = "USER-EDITED-MARKER" ] && ok "existing policy not clobbered" || bad "policy was overwritten (notes=$marker)"

# ---------------------------------------------------------------------------
# Case 3: uninstall removes only our entry; the unrelated hook remains.
# ---------------------------------------------------------------------------
"$PY" "$INSTALL" --uninstall >/dev/null 2>&1
rc=$?
[ "$rc" -eq 0 ] && ok "uninstall exits 0" || bad "uninstall exit $rc"

[ "$(gate_count)" = "0" ] && ok "gate hook removed by uninstall" || bad "gate hook survived uninstall (count=$(gate_count))"

if has_command_substr "echo unrelated-guard"; then
  ok "unrelated hook survived uninstall"
else
  bad "uninstall removed the unrelated hook too"
fi

[ -f "$POLICY" ] && ok "policy file kept after plain uninstall" || bad "plain uninstall deleted the policy"

# ---------------------------------------------------------------------------
# Case 4: fresh HOME, no prior settings — install still wires the gate.
# ---------------------------------------------------------------------------
FRESH="$(mktemp -d 2>/dev/null || mktemp -d -t aws-ops-install2)"
(
  export HOME="$FRESH"
  export AWS_OPS_ZSHRC="$FRESH/.zshrc"
  "$PY" "$INSTALL" --no-doctor >/dev/null 2>&1
)
if [ -f "$FRESH/.claude/settings.json" ] \
   && "$PY" - "$FRESH/.claude/settings.json" "$GATE" <<'PYEOF'
import json, sys
data = json.load(open(sys.argv[1]))
gate = sys.argv[2]
ok = any(
    isinstance(h, dict) and gate in str(h.get("command",""))
    for e in data.get("hooks", {}).get("PreToolUse", []) if isinstance(e, dict)
    for h in (e.get("hooks") or [])
)
sys.exit(0 if ok else 1)
PYEOF
then
  ok "fresh install created settings.json with the gate"
else
  bad "fresh install did not wire the gate"
fi
[ -f "$FRESH/.claude/aws-ops.policy.json" ] && ok "fresh install scaffolded policy" || bad "fresh install missing policy"
rm -rf "$FRESH"

# ---------------------------------------------------------------------------
# Case 5: --with-shim appends an idempotent source line; --purge reverts it.
# ---------------------------------------------------------------------------
run_install --with-shim
lines="$(grep -c "aws-shim.sh" "$AWS_OPS_ZSHRC" 2>/dev/null)"; lines="${lines:-0}"
[ "$lines" = "1" ] && ok "shim source line added once" || bad "shim line count=$lines, expected 1"

run_install --with-shim
lines="$(grep -c "aws-shim.sh" "$AWS_OPS_ZSHRC" 2>/dev/null)"; lines="${lines:-0}"
[ "$lines" = "1" ] && ok "shim source line is idempotent" || bad "shim line duplicated (count=$lines)"

"$PY" "$INSTALL" --uninstall --purge >/dev/null 2>&1
[ ! -f "$POLICY" ] && ok "--purge deleted the policy file" || bad "--purge left the policy file"
lines="$(grep -c "aws-shim.sh" "$AWS_OPS_ZSHRC" 2>/dev/null)"; lines="${lines:-0}"
[ "$lines" = "0" ] && ok "--purge removed the shim source line" || bad "shim line survived --purge (count=$lines)"

# ---------------------------------------------------------------------------
# Case 6: a corrupt settings file fails closed and is left untouched.
# ---------------------------------------------------------------------------
printf '{ this is not valid json ' > "$SETTINGS"
before="$(cat "$SETTINGS")"
"$PY" "$INSTALL" --no-doctor >/dev/null 2>&1
rc=$?
[ "$rc" -ne 0 ] && ok "corrupt settings makes install fail closed (exit $rc)" || bad "install did not fail on corrupt settings"
after="$(cat "$SETTINGS")"
[ "$before" = "$after" ] && ok "corrupt settings file left untouched" || bad "installer overwrote a corrupt settings file"

# ---------------------------------------------------------------------------
echo
echo "Summary: $pass pass, $fail fail"
[ "$fail" -eq 0 ] || exit 1
echo "All installer tests passed."
