#!/usr/bin/env python3
"""Offline contract tests for aws-ops-doctor.py policy validation."""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
DOCTOR_PATH = HERE / "aws-ops-doctor.py"
SPEC = importlib.util.spec_from_file_location("aws_ops_doctor_under_test", DOCTOR_PATH)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - import bootstrap
    raise RuntimeError(f"could not load {DOCTOR_PATH}")
DOCTOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DOCTOR)

VALID_POLICY = {
    "operator": {"name": "offline-test", "stamp_prefix": "test-operator"},
    "profiles": {"test-read": "readonly", "test-admin": "admin"},
    "required_tags": {},
    "ledger": False,
}


class DoctorPolicyContractTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.original_policy = DOCTOR.POLICY_JSON
        self.original_alias = DOCTOR.AWS_ALIAS_FILE
        self.original_runtime = DOCTOR.CODEX_RUNTIME
        self.original_quiet = DOCTOR.QUIET
        DOCTOR.CODEX_RUNTIME = True
        DOCTOR.QUIET = True

    def tearDown(self):
        DOCTOR.POLICY_JSON = self.original_policy
        DOCTOR.AWS_ALIAS_FILE = self.original_alias
        DOCTOR.CODEX_RUNTIME = self.original_runtime
        DOCTOR.QUIET = self.original_quiet
        DOCTOR.results.clear()
        self.tempdir.cleanup()

    def write_policy(self, payload=VALID_POLICY, *, name="policy.json", mode=0o600):
        path = self.root / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        path.chmod(mode)
        return path

    def write_raw_policy(self, raw, *, name="policy.json", mode=0o600):
        path = self.root / name
        path.write_text(raw, encoding="utf-8")
        path.chmod(mode)
        return path

    def run_policy_check(self, path):
        DOCTOR.POLICY_JSON = Path(path)
        DOCTOR.results.clear()
        DOCTOR.check_policy()
        self.assertEqual(len(DOCTOR.results), 1)
        return DOCTOR.results[0]

    def assert_policy_fails(self, path, message_fragment):
        status, name, reason = self.run_policy_check(path)
        self.assertEqual(name, "policy file")
        self.assertEqual(status, DOCTOR.FAIL, reason)
        self.assertIn(message_fragment, reason)

    def run_doctor_process(self, path, *args):
        env = dict(os.environ)
        env.update(
            {
                "AWS_OPS_HOOK_RUNTIME": "codex",
                "AWS_OPS_MODE": "readonly",
                "AWS_OPS_POLICY_FILE": str(path),
                "AWS_OPS_LEDGER_FILE": os.devnull,
                "AWS_OPS_TRUSTED_AWS_CLI": "/usr/bin/true",
                "PLUGIN_ROOT": str(DOCTOR_PATH.parents[3]),
            }
        )
        started = time.monotonic()
        result = subprocess.run(
            [sys.executable, str(DOCTOR_PATH), *args],
            text=True,
            capture_output=True,
            env=env,
            timeout=5,
            check=False,
        )
        self.assertLess(time.monotonic() - started, 4.5)
        return result

    def run_alias_check(self, path):
        DOCTOR.AWS_ALIAS_FILE = Path(path)
        DOCTOR.results.clear()
        DOCTOR.check_aws_cli_aliases()
        self.assertEqual(len(DOCTOR.results), 1)
        return DOCTOR.results[0]

    def test_accepts_secure_policy_with_readonly_profile(self):
        status, _, reason = self.run_policy_check(self.write_policy())
        self.assertEqual(status, DOCTOR.PASS, reason)

    def test_rejects_active_aws_cli_aliases(self):
        alias = self.root / "alias"
        alias.write_text(
            "[command sts]\nget-caller-identity = !printf offline-only\n",
            encoding="utf-8",
        )
        status, name, reason = self.run_alias_check(alias)
        self.assertEqual(name, "AWS CLI aliases")
        self.assertEqual(status, DOCTOR.FAIL, reason)
        self.assertIn("replace", reason)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO check")
    def test_rejects_aws_alias_fifo_without_blocking(self):
        alias = self.root / "alias-fifo"
        os.mkfifo(alias, 0o600)
        started = time.monotonic()
        status, _, reason = self.run_alias_check(alias)
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertEqual(status, DOCTOR.FAIL, reason)
        self.assertIn("regular file", reason)

    def test_rejects_symbolic_link(self):
        target = self.write_policy(name="target.json")
        link = self.root / "policy-link.json"
        link.symlink_to(target)
        self.assert_policy_fails(link, "symbolic link")

    def test_rejects_non_regular_file(self):
        directory = self.root / "policy-directory"
        directory.mkdir()
        self.assert_policy_fails(directory, "regular file")

        if hasattr(os, "mkfifo"):
            fifo = self.root / "policy-fifo"
            os.mkfifo(fifo, 0o600)
            self.assert_policy_fails(fifo, "regular file")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO check")
    def test_full_doctor_and_session_reject_fifo_without_blocking(self):
        fifo = self.root / "policy-fifo-process"
        os.mkfifo(fifo, 0o600)
        quick = self.run_doctor_process(fifo, "--quick")
        self.assertEqual(quick.returncode, 1, quick.stdout + quick.stderr)
        self.assertIn("regular file", quick.stdout)
        session = self.run_doctor_process(fifo, "--session")
        self.assertEqual(session.returncode, 0, session.stderr)
        message = json.loads(session.stdout)
        self.assertIn("systemMessage", message)

    def test_full_doctor_rejects_oversized_policy_without_blocking(self):
        path = self.root / "oversized-process.json"
        with path.open("wb") as stream:
            stream.truncate(DOCTOR.MAX_POLICY_BYTES + 1)
        path.chmod(0o600)
        quick = self.run_doctor_process(path, "--quick")
        self.assertEqual(quick.returncode, 1, quick.stdout + quick.stderr)
        self.assertIn("exceeds", quick.stdout)

    @unittest.skipUnless(hasattr(os, "getuid"), "POSIX ownership check")
    def test_rejects_file_owned_by_another_uid(self):
        path = self.write_policy()
        real_getuid = DOCTOR.os.getuid
        owner = path.stat().st_uid
        DOCTOR.os.getuid = lambda: owner + 1
        try:
            self.assert_policy_fails(path, "owned by the current user")
        finally:
            DOCTOR.os.getuid = real_getuid

    def test_requires_mode_exactly_0600(self):
        for index, mode in enumerate((0o400, 0o640, 0o644)):
            with self.subTest(mode=f"{mode:04o}"):
                path = self.write_policy(name=f"mode-{index}.json", mode=mode)
                self.assert_policy_fails(path, "permissions must be 600")

    def test_rejects_invalid_json_and_non_object_top_level(self):
        self.assert_policy_fails(self.write_raw_policy("{"), "not valid JSON")
        self.assert_policy_fails(
            self.write_policy([], name="array.json"),
            "top level must be a JSON object",
        )

    def test_rejects_oversized_policy_before_parsing(self):
        path = self.root / "oversized.json"
        with path.open("wb") as stream:
            stream.truncate(DOCTOR.MAX_POLICY_BYTES + 1)
        path.chmod(0o600)
        self.assert_policy_fails(path, "exceeds")

    def test_rejects_invalid_container_and_scalar_types(self):
        cases = (
            (
                "operator",
                {**VALID_POLICY, "operator": []},
                "operator must be an object",
            ),
            (
                "stamp",
                {**VALID_POLICY, "operator": {"stamp_prefix": 123}},
                "operator.stamp_prefix missing",
            ),
            (
                "profiles",
                {**VALID_POLICY, "profiles": []},
                "profiles must be an object",
            ),
            (
                "tags",
                {**VALID_POLICY, "required_tags": []},
                "required_tags must be an object",
            ),
        )
        for index, (label, policy, expected) in enumerate(cases):
            with self.subTest(case=label):
                path = self.write_policy(policy, name=f"types-{index}.json")
                self.assert_policy_fails(path, expected)

    def test_rejects_empty_profiles(self):
        policy = {**VALID_POLICY, "profiles": {}}
        self.assert_policy_fails(
            self.write_policy(policy), "profiles must classify at least one profile"
        )

    def test_requires_at_least_one_readonly_profile(self):
        policy = {**VALID_POLICY, "profiles": {"test-admin": "admin"}}
        self.assert_policy_fails(
            self.write_policy(policy), "at least one readonly profile"
        )

    def test_rejects_unsupported_profile_class(self):
        for index, invalid_class in enumerate(("poweruser", ["readonly"])):
            with self.subTest(invalid_class=invalid_class):
                policy = {
                    **VALID_POLICY,
                    "profiles": {
                        "test-read": "readonly",
                        "test-bad": invalid_class,
                    },
                }
                path = self.write_policy(policy, name=f"class-{index}.json")
                self.assert_policy_fails(path, "invalid class")

    def test_validates_allowed_environment(self):
        valid = {
            **VALID_POLICY,
            "allowed_environment": {"SSL_CERT_FILE": "/tmp/corporate-ca.pem"},
        }
        status, _, reason = self.run_policy_check(self.write_policy(valid))
        self.assertEqual(status, DOCTOR.PASS, reason)

        unsupported = {
            **VALID_POLICY,
            "allowed_environment": {"PYTHONPATH": "/tmp/attacker"},
        }
        self.assert_policy_fails(
            self.write_policy(unsupported, name="unsupported-env.json"),
            "unsupported keys",
        )

        invalid = {**VALID_POLICY, "allowed_environment": {"SSL_CERT_FILE": ""}}
        self.assert_policy_fails(
            self.write_policy(invalid, name="invalid-env.json"),
            "invalid values",
        )

    def test_requires_lowercase_kebab_case_stamp_prefix(self):
        for index, prefix in enumerate(
            ("UPPER", "bad_prefix", "bad--prefix", "-leading", "trailing-")
        ):
            with self.subTest(prefix=prefix):
                policy = {
                    **VALID_POLICY,
                    "operator": {"name": "offline-test", "stamp_prefix": prefix},
                }
                path = self.write_policy(policy, name=f"stamp-{index}.json")
                self.assert_policy_fails(path, "lowercase kebab-case")

    def test_claude_preserves_optional_policy_file_contract(self):
        DOCTOR.CODEX_RUNTIME = False
        policy = {
            "operator": {"stamp_prefix": "Legacy_Prefix"},
            "profiles": {"legacy-admin": "admin"},
        }
        path = self.write_policy(policy, mode=0o644)
        status, _, reason = self.run_policy_check(path)
        self.assertEqual(status, DOCTOR.PASS, reason)


if __name__ == "__main__":
    unittest.main(verbosity=2)
