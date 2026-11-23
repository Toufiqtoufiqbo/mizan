"""Trusted law declarations: no field or bound is inferred from a name."""

from __future__ import annotations

import pytest

from mizan.ownership import CardinalityInvariant, ProtectedField, RelationshipContract, RelationshipContractError


def _data() -> dict:
    return {
        "version": 1,
        "identity": {"endpoint": "/whoami", "field": "p_key"},
        "authority": {
            "fields": [
                {
                    "resource_type": "users",
                    "field": "role",
                    "source": "trusted_contract",
                    "confidence": "confirmed",
                    "authorized_roles": ["admin"],
                    "table": "users",
                }
            ]
        },
        "cardinality": [
            {
                "resource_type": "items",
                "bound": 2,
                "scope": "principal",
                "unit": "objects",
                "source": "trusted_contract",
                "enforcement": "reject_beyond",
                "table": "inventory_items",
            }
        ],
    }


def test_trusted_declarations_are_parsed() -> None:
    contract = RelationshipContract.from_dict(_data(), strict=True)
    assert contract.protected_fields == (
        ProtectedField(
            resource_type="users",
            field="role",
            source="trusted_contract",
            confidence="confirmed",
            authorized_roles=frozenset({"admin"}),
            table="users",
        ),
    )
    assert contract.cardinality == (
        CardinalityInvariant(
            resource_type="items",
            bound=2,
            scope="principal",
            unit="objects",
            source="trusted_contract",
            enforcement="reject_beyond",
            table="inventory_items",
        ),
    )


def test_a_field_name_alone_never_creates_a_policy() -> None:
    contract = RelationshipContract.from_dict(
        {"version": 1, "authority": {"fields": [{"resource_type": "users", "field": "role"}]}}, strict=False
    )
    assert contract.protected_fields == ()
    with pytest.raises(RelationshipContractError):
        RelationshipContract.from_dict(
            {"version": 1, "authority": {"fields": [{"resource_type": "users", "field": "role"}]}}, strict=True
        )


def test_source_and_confidence_are_mandatory_in_strict_mode() -> None:
    data = _data()
    del data["authority"]["fields"][0]["source"]
    with pytest.raises(RelationshipContractError, match="source and confidence"):
        RelationshipContract.from_dict(data, strict=True)


def test_cardinality_verification_is_typed_and_bounded() -> None:
    data = _data()
    data["cardinality"][0]["bound"] = "many"
    with pytest.raises(RelationshipContractError, match="non-negative integer"):
        RelationshipContract.from_dict(data, strict=True)
    data = _data()
    data["cardinality"][0]["enforcement"] = "vibes"
    with pytest.raises(RelationshipContractError, match="unsupported cardinality enforcement"):
        RelationshipContract.from_dict(data, strict=True)


def test_variant_merge_keeps_law_declarations() -> None:
    data = _data()
    data["variants"] = {
        "loose": {
            "cardinality": [
                {
                    "resource_type": "items",
                    "bound": 5,
                    "scope": "principal",
                    "unit": "objects",
                    "source": "trusted_contract",
                    "enforcement": "reject_beyond",
                    "table": "inventory_items",
                }
            ]
        }
    }
    contract = RelationshipContract.from_dict(data, strict=True)
    merged = contract.for_variant("loose", strict=True)
    assert merged.protected_fields == contract.protected_fields
    assert merged.cardinality[0].bound == 5
