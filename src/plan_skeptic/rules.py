"""Review rules.

Every rule reports what a change *introduces*, not what the resource already
was: an update that leaves an existing 0.0.0.0/0 rule alone is not this plan's
decision, and a reviewer who is shown every pre-existing problem on every plan
stops reading the output. Creates are judged on `after` alone; updates and
replacements are judged on whether `before` already had the property.

Unknown-after-apply values arrive as `null` in `after` and never trigger a rule.
That is a deliberate false negative: guessing at a value Terraform itself cannot
see yet would put invented findings in front of the reviewer.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable, Iterable

from .plan import ResourceChange

HIGH = "high"
MEDIUM = "medium"
LOW = "low"
SEVERITY_ORDER = {LOW: 1, MEDIUM: 2, HIGH: 3}


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str
    summary: str
    why: str


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    address: str
    message: str
    # Distinguishes multiple findings of the same rule on one address in SARIF
    # fingerprints. Must not be the free-text message: wording changes would
    # reopen alerts as new.
    key: str = ""


RULES = {
    r.id: r
    for r in (
        Rule(
            "PS001", "stateful-resource-replaced", HIGH,
            "A resource that holds data is being destroyed or replaced.",
            "Replacement is destroy-then-create unless create_before_destroy is set. "
            "An AI-suggested attribute tweak (engine version, subnet group, name) that "
            "forces replacement reads like an edit in the diff and deletes the data.",
        ),
        Rule(
            "PS002", "resource-deleted", MEDIUM,
            "A resource is being deleted.",
            "Deletions are the change a reviewer most often skims past. Confirm the "
            "resource is really unused and not merely moved to another address "
            "(use a `moved` block instead).",
        ),
        Rule(
            "PS003", "iam-policy-wildcard", HIGH,
            "An IAM policy grants a wildcard action or uses NotAction in an Allow.",
            "`service:*` and `*` grant every current and future action. Generated "
            "policies widen to wildcards to make an error go away; the error was "
            "the least-privilege boundary working.",
        ),
        Rule(
            "PS004", "broad-managed-policy-attached", HIGH,
            "An administrator-level AWS managed policy is being attached.",
            "AdministratorAccess, PowerUserAccess and IAMFullAccess each amount to "
            "full account control. Attaching one is an access decision, not an "
            "infrastructure change.",
        ),
        Rule(
            "PS005", "trust-policy-any-principal", HIGH,
            "A role's trust policy allows any principal to assume it.",
            "A Principal of `*` with no Condition lets any AWS account assume the role.",
        ),
        Rule(
            "PS006", "ingress-open-to-world", HIGH,
            "A security group rule opens a port to 0.0.0.0/0 or ::/0.",
            "Opening SSH, RDP or a database port to the internet is the classic "
            "'make the connection work' fix. Ports 80 and 443 are reported at medium, "
            "since public web ingress is often intended.",
        ),
        Rule(
            "PS007", "s3-public-access", HIGH,
            "An S3 bucket is being made publicly readable or writable.",
            "Public ACLs, a relaxed public access block, or a bucket policy granting "
            "`*` without a Condition expose every object in the bucket.",
        ),
        Rule(
            "PS008", "database-publicly-accessible", HIGH,
            "A database is being given a public endpoint.",
            "publicly_accessible = true places the database on the internet, "
            "protected only by its security groups and password.",
        ),
        Rule(
            "PS009", "encryption-disabled", MEDIUM,
            "Encryption at rest is set to false.",
            "Turning encryption on later usually forces replacement, so a resource "
            "created unencrypted tends to stay that way.",
        ),
        Rule(
            "PS010", "recovery-guard-removed", MEDIUM,
            "A guard against accidental data loss is being switched off.",
            "deletion_protection, skip_final_snapshot and force_destroy exist to make "
            "the next mistake recoverable. Turning one off is often the first step "
            "of a plan that deletes something in a later apply.",
        ),
        Rule(
            "PS011", "kms-key-policy-any-principal", HIGH,
            "A KMS key policy allows any principal without a Condition.",
            "A Principal of `*` with no Condition lets any AWS account use the key. "
            "Generated policies open this to make encrypt/decrypt errors go away.",
        ),
    )
}

STATEFUL_TYPES = frozenset({
    "aws_db_instance", "aws_rds_cluster", "aws_rds_cluster_instance",
    "aws_dynamodb_table", "aws_s3_bucket", "aws_efs_file_system", "aws_ebs_volume",
    "aws_elasticache_cluster", "aws_elasticache_replication_group",
    "aws_redshift_cluster", "aws_docdb_cluster", "aws_neptune_cluster",
    "aws_opensearch_domain", "aws_elasticsearch_domain", "aws_msk_cluster",
    "aws_kms_key", "aws_secretsmanager_secret",
    "google_sql_database_instance", "google_storage_bucket", "google_compute_disk",
    "google_bigquery_dataset", "google_bigquery_table", "google_spanner_instance",
    "azurerm_storage_account", "azurerm_mssql_database", "azurerm_mssql_server",
    "azurerm_postgresql_flexible_server", "azurerm_mysql_flexible_server",
    "azurerm_cosmosdb_account", "azurerm_managed_disk", "azurerm_key_vault",
    "kubernetes_persistent_volume_claim", "kubernetes_persistent_volume_claim_v1",
    "kubernetes_persistent_volume", "kubernetes_persistent_volume_v1",
})

IAM_POLICY_TYPES = frozenset({
    "aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy",
})
# aws_iam_role carries nested inline_policy blocks; same wildcard rules apply.
IAM_WILDCARD_TYPES = IAM_POLICY_TYPES | {"aws_iam_role"}
POLICY_ATTACHMENT_TYPES = frozenset({
    "aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment",
    "aws_iam_group_policy_attachment", "aws_iam_policy_attachment",
})
BROAD_MANAGED_POLICIES = ("AdministratorAccess", "PowerUserAccess", "IAMFullAccess")
PUBLIC_DB_TYPES = frozenset({"aws_db_instance", "aws_rds_cluster_instance", "aws_redshift_cluster"})
WORLD_CIDRS = frozenset({"0.0.0.0/0", "::/0"})
PUBLIC_ACLS = frozenset({"public-read", "public-read-write", "authenticated-read"})
WEB_PORTS = frozenset({80, 443})

ENCRYPTION_FLAGS = {
    "aws_db_instance": "storage_encrypted",
    "aws_rds_cluster": "storage_encrypted",
    "aws_docdb_cluster": "storage_encrypted",
    "aws_neptune_cluster": "storage_encrypted",
    "aws_ebs_volume": "encrypted",
    "aws_efs_file_system": "encrypted",
    "aws_redshift_cluster": "encrypted",
    "aws_elasticache_replication_group": "at_rest_encryption_enabled",
}
# attribute -> the value that removes the guard
RECOVERY_GUARDS = {
    "deletion_protection": False,
    "deletion_protection_enabled": False,
    "skip_final_snapshot": True,
    "force_destroy": True,
}


def _introduced(rc: ResourceChange, test: Callable[[dict], bool]) -> bool:
    if not rc.writes or not test(rc.after):
        return False
    return rc.is_create or not test(rc.before)


def _new_items(rc: ResourceChange, extract: Callable[[dict], set]) -> list:
    if not rc.writes:
        return []
    after = extract(rc.after)
    before = set() if rc.is_create else extract(rc.before)
    return sorted(after - before, key=str)


def _finding(
    rule_id: str, rc: ResourceChange, message: str, severity: str = "", key: str = "",
) -> Finding:
    return Finding(rule_id, severity or RULES[rule_id].severity, rc.address, message, key)


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _policy_statements(doc) -> list:
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except (json.JSONDecodeError, TypeError):
            return []
    if not isinstance(doc, dict):
        return []
    return [s for s in _as_list(doc.get("Statement")) if isinstance(s, dict)]


def _allows(stmt: dict) -> bool:
    return stmt.get("Effect", "Allow") == "Allow"


def _principal_is_anyone(principal) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        return any("*" in _as_list(v) for v in principal.values())
    return False


def _policy_allows_anyone(doc) -> bool:
    return any(
        _allows(s) and _principal_is_anyone(s.get("Principal")) and not s.get("Condition")
        for s in _policy_statements(doc)
    )


def _policy_docs(values: dict) -> list:
    """Policy documents on a resource: top-level `policy` plus role inline_policy blocks."""
    docs = [values.get("policy")]
    for block in _as_list(values.get("inline_policy")):
        if isinstance(block, dict):
            docs.append(block.get("policy"))
    return docs


def _wildcard_grants(values: dict) -> set:
    grants = set()
    for doc in _policy_docs(values):
        for stmt in _policy_statements(doc):
            if not _allows(stmt):
                continue
            for action in _as_list(stmt.get("Action")):
                if isinstance(action, str) and (action == "*" or action.endswith(":*")):
                    grants.add(f"Action {action}")
            if stmt.get("NotAction") is not None:
                grants.add("NotAction in an Allow statement")
    return grants


def _anyone_can_assume(values: dict) -> bool:
    return _policy_allows_anyone(values.get("assume_role_policy"))


def _bucket_policy_public(values: dict) -> bool:
    return _policy_allows_anyone(values.get("policy"))


def _kms_policy_anyone(values: dict) -> bool:
    return _policy_allows_anyone(values.get("policy"))


def _port_label(from_port, to_port) -> str:
    if from_port in (None, -1, 0) and to_port in (None, -1, 0, 65535):
        return "all ports"
    if from_port == to_port:
        return f"port {from_port}"
    return f"ports {from_port}-{to_port}"


def _world_ingress(rc_type: str, values: dict) -> set:
    """(from_port, to_port, cidr) tuples reachable from the whole internet."""
    rules = []
    if rc_type == "aws_security_group":
        rules = [r for r in _as_list(values.get("ingress")) if isinstance(r, dict)]
    elif rc_type == "aws_security_group_rule":
        if values.get("type") == "ingress":
            rules = [values]
    elif rc_type == "aws_vpc_security_group_ingress_rule":
        rules = [{
            "from_port": values.get("from_port"),
            "to_port": values.get("to_port"),
            "cidr_blocks": [values.get("cidr_ipv4")],
            "ipv6_cidr_blocks": [values.get("cidr_ipv6")],
        }]
    found = set()
    for r in rules:
        cidrs = _as_list(r.get("cidr_blocks")) + _as_list(r.get("ipv6_cidr_blocks"))
        for cidr in cidrs:
            if cidr in WORLD_CIDRS:
                found.add((r.get("from_port"), r.get("to_port"), cidr))
    return found


def _is_web_only(from_port, to_port) -> bool:
    return from_port == to_port and from_port in WEB_PORTS


def check_stateful_replaced(rc: ResourceChange) -> Iterable[Finding]:
    if rc.type not in STATEFUL_TYPES or not (rc.is_replace or rc.is_delete):
        return
    if rc.is_delete:
        yield _finding("PS001", rc, f"{rc.type} will be destroyed.")
        return
    cause = ""
    if rc.replace_paths:
        cause = " because " + ", ".join(".".join(str(p) for p in path) for path in rc.replace_paths) + " changed"
    order = "created before the old one is destroyed" if rc.actions[0] == "create" else "destroyed, then recreated empty"
    yield _finding("PS001", rc, f"{rc.type} will be replaced{cause}: {order}.")


def check_deleted(rc: ResourceChange) -> Iterable[Finding]:
    if rc.is_delete and rc.type not in STATEFUL_TYPES:
        yield _finding("PS002", rc, f"{rc.type} will be deleted.")


def check_iam_wildcard(rc: ResourceChange) -> Iterable[Finding]:
    if rc.type not in IAM_WILDCARD_TYPES:
        return
    for grant in _new_items(rc, _wildcard_grants):
        yield _finding("PS003", rc, f"Policy now grants {grant}.", key=grant)


def check_broad_attachment(rc: ResourceChange) -> Iterable[Finding]:
    def broad(values: dict) -> set:
        arns = []
        if rc.type in POLICY_ATTACHMENT_TYPES:
            arns = [values.get("policy_arn")]
        elif rc.type == "aws_iam_role":
            arns = _as_list(values.get("managed_policy_arns"))
        return {
            name for arn in arns if isinstance(arn, str)
            for name in BROAD_MANAGED_POLICIES if arn.endswith(":policy/" + name)
        }

    for name in _new_items(rc, broad):
        yield _finding("PS004", rc, f"Attaches the AWS managed policy {name}.", key=name)


def check_trust_anyone(rc: ResourceChange) -> Iterable[Finding]:
    if rc.type == "aws_iam_role" and _introduced(rc, _anyone_can_assume):
        yield _finding("PS005", rc, "Trust policy allows Principal * with no Condition.")


def check_open_ingress(rc: ResourceChange) -> Iterable[Finding]:
    for from_port, to_port, cidr in _new_items(rc, lambda v: _world_ingress(rc.type, v)):
        severity = MEDIUM if _is_web_only(from_port, to_port) else HIGH
        label = _port_label(from_port, to_port)
        yield _finding(
            "PS006", rc, f"Opens {label} to {cidr}.", severity,
            key=f"{from_port}-{to_port}-{cidr}",
        )


def check_s3_public(rc: ResourceChange) -> Iterable[Finding]:
    if rc.type == "aws_s3_bucket_public_access_block":
        flags = ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")
        off = _new_items(rc, lambda v: {f for f in flags if v.get(f) is False})
        if off:
            yield _finding(
                "PS007", rc, "Public access block disables " + ", ".join(off) + ".",
                key=",".join(off),
            )
    elif rc.type in ("aws_s3_bucket_acl", "aws_s3_bucket"):
        if _introduced(rc, lambda v: v.get("acl") in PUBLIC_ACLS):
            yield _finding("PS007", rc, f"Bucket ACL set to {rc.after.get('acl')}.", key="acl")
    elif rc.type == "aws_s3_bucket_policy":
        if _introduced(rc, _bucket_policy_public):
            yield _finding("PS007", rc, "Bucket policy allows Principal * with no Condition.", key="policy")


def check_public_database(rc: ResourceChange) -> Iterable[Finding]:
    if rc.type in PUBLIC_DB_TYPES and _introduced(rc, lambda v: v.get("publicly_accessible") is True):
        yield _finding("PS008", rc, "publicly_accessible = true.")


def check_encryption_disabled(rc: ResourceChange) -> Iterable[Finding]:
    attr = ENCRYPTION_FLAGS.get(rc.type)
    if attr and _introduced(rc, lambda v: v.get(attr) is False):
        yield _finding("PS009", rc, f"{attr} = false.", key=attr)


def check_recovery_guards(rc: ResourceChange) -> Iterable[Finding]:
    if not (rc.is_update or rc.is_replace or (rc.is_create and rc.type in STATEFUL_TYPES)):
        return
    for attr, unsafe in RECOVERY_GUARDS.items():
        if attr not in rc.after:
            continue
        if rc.is_create:
            # Defaults on a new resource are not a change a reviewer can weigh,
            # except skip_final_snapshot/force_destroy, which are opt-in.
            if attr in ("skip_final_snapshot", "force_destroy") and rc.after.get(attr) is unsafe:
                yield _finding(
                    "PS010", rc, f"{attr} = {str(unsafe).lower()} on a new data store.", key=attr,
                )
        elif rc.after.get(attr) is unsafe and rc.before.get(attr) is (not unsafe):
            yield _finding(
                "PS010", rc,
                f"{attr} changes {str(not unsafe).lower()} -> {str(unsafe).lower()}.",
                key=attr,
            )


def check_kms_anyone(rc: ResourceChange) -> Iterable[Finding]:
    if rc.type == "aws_kms_key" and _introduced(rc, _kms_policy_anyone):
        yield _finding("PS011", rc, "Key policy allows Principal * with no Condition.")


CHECKS = (
    check_stateful_replaced,
    check_deleted,
    check_iam_wildcard,
    check_broad_attachment,
    check_trust_anyone,
    check_open_ingress,
    check_s3_public,
    check_public_database,
    check_encryption_disabled,
    check_recovery_guards,
    check_kms_anyone,
)


def _moved_candidates(changes: list) -> dict:
    """Map a deleted address to the create that looks like the same object.

    A delete plus a create of the same type carrying the same `name` is what a
    refactor into a module looks like when nobody wrote a `moved` block, and
    that plan destroys the object rather than re-addressing it.
    """
    creates = {}
    for rc in changes:
        name = rc.after.get("name") or rc.after.get("identifier") or rc.after.get("bucket")
        if rc.is_create and isinstance(name, str):
            creates.setdefault((rc.type, name), rc.address)
    found = {}
    for rc in changes:
        name = rc.before.get("name") or rc.before.get("identifier") or rc.before.get("bucket")
        if rc.is_delete and isinstance(name, str) and (rc.type, name) in creates:
            found[rc.address] = creates[(rc.type, name)]
    return found


def review(changes: Iterable[ResourceChange], disabled: Iterable[str] = ()) -> list:
    changes = list(changes)
    skip = {d.upper() for d in disabled}
    moved = _moved_candidates(changes)
    findings = []
    for rc in changes:
        for check in CHECKS:
            for f in check(rc):
                if f.rule_id in skip:
                    continue
                if f.rule_id in ("PS001", "PS002") and rc.address in moved:
                    f = Finding(
                        f.rule_id, f.severity, f.address,
                        f"{f.message} The same object is created at {moved[rc.address]}; "
                        "if this is a refactor, add a `moved` block instead.",
                        f.key,
                    )
                findings.append(f)
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.rule_id, f.address))
    return findings
