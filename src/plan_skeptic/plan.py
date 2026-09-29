"""Load `terraform show -json` / `tofu show -json` output into resource changes."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


class PlanError(ValueError):
    """The input is not a machine-readable plan we can review."""


@dataclass(frozen=True)
class ResourceChange:
    address: str
    type: str
    actions: tuple
    before: dict = field(default_factory=dict)
    after: dict = field(default_factory=dict)
    replace_paths: tuple = ()

    @property
    def is_create(self) -> bool:
        return self.actions == ("create",)

    @property
    def is_update(self) -> bool:
        return self.actions == ("update",)

    @property
    def is_delete(self) -> bool:
        return self.actions == ("delete",)

    @property
    def is_replace(self) -> bool:
        return set(self.actions) == {"create", "delete"}

    @property
    def writes(self) -> bool:
        """True when the resource will exist afterwards with `after` values."""
        return self.is_create or self.is_update or self.is_replace


def load_plan(text: str) -> list:
    """Parse plan JSON text into managed-resource changes.

    Refuses a binary plan file or a state file rather than reporting "no
    findings", because an empty review of the wrong input reads as a clean plan.
    """
    try:
        doc = json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise PlanError(
            "input is not JSON; pass the output of `terraform show -json plan.out`, "
            "not the binary plan file"
        ) from exc
    if not isinstance(doc, dict):
        raise PlanError("plan JSON must be an object")
    if "resource_changes" not in doc:
        if "values" in doc and "planned_values" not in doc:
            raise PlanError("this looks like state (`show -json` without a plan file), not a plan")
        raise PlanError("no `resource_changes` key; is this `show -json` output of a saved plan?")

    changes = []
    for rc in doc.get("resource_changes") or []:
        if not isinstance(rc, dict) or rc.get("mode", "managed") != "managed":
            continue
        change = rc.get("change") or {}
        actions = tuple(change.get("actions") or ())
        if actions in ((), ("no-op",), ("read",)):
            continue
        changes.append(
            ResourceChange(
                address=str(rc.get("address", "")),
                type=str(rc.get("type", "")),
                actions=actions,
                before=_as_dict(change.get("before")),
                after=_as_dict(change.get("after")),
                replace_paths=tuple(
                    tuple(p) if isinstance(p, list) else (p,)
                    for p in (change.get("replace_paths") or [])
                ),
            )
        )
    return changes


def _as_dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}
