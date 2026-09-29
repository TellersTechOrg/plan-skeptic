"""Tests use the stdlib runner so the repo has no dependencies at all:

    python -m unittest discover -s tests
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from plan_skeptic.cli import main  # noqa: E402
from plan_skeptic.plan import PlanError, load_plan  # noqa: E402
from plan_skeptic.rules import RULES, review  # noqa: E402

FIXTURES = os.path.join(ROOT, "fixtures")


def fixture(rel: str) -> str:
    with open(os.path.join(FIXTURES, rel), encoding="utf-8") as fh:
        return fh.read()


def findings_for(rel: str) -> set:
    return {(f.rule_id, f.severity, f.address) for f in review(load_plan(fixture(rel)))}


def run_cli(*argv) -> tuple:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


def plan_with(*changes) -> str:
    return json.dumps({"format_version": "1.2", "resource_changes": list(changes)})


def change(address, rtype, actions, before=None, after=None, **extra) -> dict:
    return {
        "address": address, "mode": "managed", "type": rtype,
        "change": dict({"actions": actions, "before": before, "after": after}, **extra),
    }


class FixtureExpectations(unittest.TestCase):
    """Each flawed fixture is a workshop exercise; its expected findings are the answer key.

    Asserting the exact set (not "at least") catches a rule that starts firing
    on the wrong resource as well as one that stops firing.
    """

    def test_quickstart_postgres_real_opentofu_output(self):
        self.assertEqual(findings_for("flawed/01-quickstart-postgres.json"), {
            ("PS003", "high", "aws_iam_role_policy.p"),
            ("PS006", "high", "aws_security_group.db"),
            ("PS008", "high", "aws_db_instance.main"),
            ("PS009", "medium", "aws_db_instance.main"),
            ("PS010", "medium", "aws_db_instance.main"),
        })

    def test_rename_replaces_database(self):
        self.assertEqual(findings_for("flawed/02-rename-replaces-database.json"), {
            ("PS001", "high", "aws_db_instance.orders"),
            ("PS010", "medium", "aws_db_instance.orders"),
        })

    def test_replace_message_names_the_cause(self):
        f = [f for f in review(load_plan(fixture("flawed/02-rename-replaces-database.json"))) if f.rule_id == "PS001"][0]
        self.assertIn("because identifier changed", f.message)
        self.assertIn("destroyed, then recreated", f.message)

    def test_iam_wildcard_creep(self):
        found = review(load_plan(fixture("flawed/03-iam-wildcard-creep.json")))
        self.assertEqual(
            sorted((f.address, f.message) for f in found),
            [
                ("aws_iam_policy.exporter", "Policy now grants Action kms:*."),
                ("aws_iam_policy.exporter", "Policy now grants Action s3:*."),
                ("aws_iam_role_policy.ci_deploy", "Policy now grants NotAction in an Allow statement."),
            ],
        )

    def test_existing_wildcard_is_not_reported_again(self):
        # ci_deploy already had ecr:* before; only the NotAction statement is new.
        found = review(load_plan(fixture("flawed/03-iam-wildcard-creep.json")))
        self.assertFalse(any("ecr:*" in f.message for f in found))

    def test_open_ssh_for_debugging(self):
        self.assertEqual(findings_for("flawed/04-open-ssh-for-debugging.json"), {
            ("PS006", "high", "aws_security_group.web"),
            ("PS006", "medium", "aws_security_group.web"),
            ("PS006", "high", "aws_vpc_security_group_ingress_rule.cache_all"),
        })

    def test_pre_existing_https_ingress_is_not_reported(self):
        found = review(load_plan(fixture("flawed/04-open-ssh-for-debugging.json")))
        self.assertFalse(any("443" in f.message for f in found))

    def test_public_bucket(self):
        self.assertEqual(findings_for("flawed/05-public-bucket-for-static-site.json"), {
            ("PS007", "high", "aws_s3_bucket_acl.assets"),
            ("PS007", "high", "aws_s3_bucket_policy.assets"),
            ("PS007", "high", "aws_s3_bucket_public_access_block.assets"),
        })

    def test_admin_to_unblock_ci(self):
        self.assertEqual(findings_for("flawed/06-admin-to-unblock-ci.json"), {
            ("PS004", "high", "aws_iam_role_policy_attachment.ci_admin"),
            ("PS005", "high", "aws_iam_role.ci"),
        })

    def test_refactor_without_moved_block(self):
        found = review(load_plan(fixture("flawed/07-refactor-without-moved-block.json")))
        self.assertEqual(
            {(f.rule_id, f.address) for f in found},
            {("PS001", "aws_dynamodb_table.orders"), ("PS002", "aws_cloudwatch_log_group.orders")},
        )
        for f in found:
            self.assertIn("moved", f.message)

    def test_clean_plan_has_no_findings(self):
        self.assertEqual(findings_for("clean/01-tags-only.json"), set())

    def test_every_rule_is_exercised_by_a_fixture(self):
        fired = set()
        for name in sorted(os.listdir(os.path.join(FIXTURES, "flawed"))):
            if name.endswith(".json"):
                fired |= {r for r, _, _ in findings_for("flawed/" + name)}
        self.assertEqual(fired, set(RULES))


class RuleEdges(unittest.TestCase):
    def test_unknown_after_apply_never_triggers(self):
        plan = plan_with(change("aws_db_instance.x", "aws_db_instance", ["create"],
                                after={"publicly_accessible": None, "storage_encrypted": None},
                                after_unknown={"publicly_accessible": True}))
        self.assertEqual(review(load_plan(plan)), [])

    def test_policy_that_is_not_json_is_ignored_not_crashed(self):
        plan = plan_with(change("aws_iam_policy.x", "aws_iam_policy", ["create"], after={"policy": "not json"}))
        self.assertEqual(review(load_plan(plan)), [])

    def test_deny_wildcard_is_not_a_grant(self):
        policy = json.dumps({"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]})
        plan = plan_with(change("aws_iam_policy.x", "aws_iam_policy", ["create"], after={"policy": policy}))
        self.assertEqual(review(load_plan(plan)), [])

    def test_trust_policy_with_condition_is_not_anyone(self):
        policy = json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole",
                                            "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-123"}}}]})
        plan = plan_with(change("aws_iam_role.x", "aws_iam_role", ["create"], after={"assume_role_policy": policy}))
        self.assertEqual(review(load_plan(plan)), [])

    def test_deletion_protection_default_on_create_is_not_reported(self):
        plan = plan_with(change("aws_db_instance.x", "aws_db_instance", ["create"],
                                after={"deletion_protection": False, "skip_final_snapshot": False}))
        self.assertEqual(review(load_plan(plan)), [])

    def test_replace_with_create_before_destroy_says_so(self):
        plan = plan_with(change("aws_s3_bucket.x", "aws_s3_bucket", ["create", "delete"], before={}, after={}))
        (f,) = review(load_plan(plan))
        self.assertIn("created before the old one is destroyed", f.message)

    def test_disable_skips_a_rule(self):
        plan = fixture("flawed/07-refactor-without-moved-block.json")
        self.assertEqual({f.rule_id for f in review(load_plan(plan), ["ps002"])}, {"PS001"})

    def test_findings_sort_high_first(self):
        found = review(load_plan(fixture("flawed/01-quickstart-postgres.json")))
        self.assertEqual([f.severity for f in found][:3], ["high"] * 3)
        self.assertEqual(found[-1].severity, "medium")


class PlanLoading(unittest.TestCase):
    def test_binary_plan_is_refused(self):
        with self.assertRaises(PlanError) as ctx:
            load_plan("PK\x03\x04 not json")
        self.assertIn("show -json", str(ctx.exception))

    def test_state_is_refused_rather_than_reported_clean(self):
        with self.assertRaises(PlanError) as ctx:
            load_plan(json.dumps({"format_version": "1.0", "values": {"root_module": {}}}))
        self.assertIn("state", str(ctx.exception))

    def test_no_op_read_and_data_sources_are_skipped(self):
        plan = plan_with(
            change("aws_s3_bucket.a", "aws_s3_bucket", ["no-op"], before={}, after={}),
            dict(change("data.x.y", "x", ["read"]), mode="data"),
        )
        self.assertEqual(load_plan(plan), [])

    def test_empty_plan_is_valid(self):
        self.assertEqual(load_plan(json.dumps({"resource_changes": []})), [])


class Cli(unittest.TestCase):
    def path(self, rel: str) -> str:
        return os.path.join(FIXTURES, rel)

    def test_exit_1_on_high_by_default(self):
        code, out, _ = run_cli(self.path("flawed/02-rename-replaces-database.json"))
        self.assertEqual(code, 1)
        self.assertIn("PS001", out)

    def test_exit_0_on_clean(self):
        code, out, _ = run_cli(self.path("clean/01-tags-only.json"))
        self.assertEqual(code, 0)
        self.assertIn("nothing flagged", out)

    def test_fail_on_threshold(self):
        # 07 has one high and one medium; disabling the high leaves a medium.
        p = self.path("flawed/07-refactor-without-moved-block.json")
        self.assertEqual(run_cli(p, "--disable", "PS001")[0], 0)
        self.assertEqual(run_cli(p, "--disable", "PS001", "--fail-on", "medium")[0], 1)
        self.assertEqual(run_cli(p, "--fail-on", "never")[0], 0)

    def test_unreadable_input_exits_2_not_0(self):
        code, _, err = run_cli(self.path("does-not-exist.json"))
        self.assertEqual(code, 2)
        self.assertIn("plan-skeptic:", err)

    def test_unknown_rule_id_exits_2(self):
        self.assertEqual(run_cli(self.path("clean/01-tags-only.json"), "--disable", "PS999")[0], 2)

    def test_sarif_is_valid_shape(self):
        code, out, _ = run_cli(self.path("flawed/05-public-bucket-for-static-site.json"), "--format", "sarif")
        self.assertEqual(code, 1)
        doc = json.loads(out)
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        self.assertEqual({r["id"] for r in run["tool"]["driver"]["rules"]}, set(RULES))
        self.assertEqual(len(run["results"]), 3)
        for result in run["results"]:
            self.assertEqual(result["level"], "error")
            loc = result["locations"][0]
            self.assertIn("physicalLocation", loc, "code scanning drops results without one")
            self.assertTrue(loc["logicalLocations"][0]["fullyQualifiedName"].startswith("aws_s3_"))

    def test_output_file_plus_text_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "out.sarif")
            code, out, _ = run_cli(self.path("flawed/06-admin-to-unblock-ci.json"),
                                   "--format", "sarif", "--output", target)
            self.assertEqual(code, 1)
            with open(target, encoding="utf-8") as fh:
                self.assertEqual(len(json.load(fh)["runs"][0]["results"]), 2)
            self.assertIn("PS004", out)

    def test_list_rules(self):
        code, out, _ = run_cli("--list-rules")
        self.assertEqual(code, 0)
        self.assertEqual(len(out.strip().splitlines()), len(RULES))


if __name__ == "__main__":
    unittest.main()
