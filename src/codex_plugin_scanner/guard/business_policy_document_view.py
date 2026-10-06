"""Policy inspection uses authenticated complete source, with provenance redaction."""

from typing import cast

from .policy_document import GuardPolicyDocument
from .policy_document_types import PolicyCompilationError


def without_provenance(document: GuardPolicyDocument) -> GuardPolicyDocument:
    value = document.to_mapping()
    spec = cast(dict[str, object], value["spec"])
    for rule in cast(list[dict[str, object]], spec["rules"]):
        match = cast(dict[str, object], rule.get("match") or {})
        if match.get("workspaces"):
            raise PolicyCompilationError("sensitive_local_policy_requires_provenance", str(rule.get("id")))
        rule.pop("description", None)
        rule["provenance"] = {"source": "export-redacted", "createdAt": "1970-01-01T00:00:00Z"}
    return GuardPolicyDocument.from_mapping(value)
