"""Policy inspection uses authenticated complete source, with provenance redaction."""

from typing import cast

from .policy_document import GuardPolicyDocument


def without_provenance(document: GuardPolicyDocument) -> GuardPolicyDocument:
    value = document.to_mapping()
    spec = cast(dict[str, object], value["spec"])
    for rule in cast(list[dict[str, object]], spec["rules"]):
        rule["provenance"] = {"source": "local", "createdAt": "1970-01-01T00:00:00Z"}
    return GuardPolicyDocument.from_mapping(value)
