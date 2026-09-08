"""Unit tests for mint policy enforcement (max lifetime, VO allowlist)."""

from __future__ import annotations

import pytest

from voms_token_service.policy import (
    InvalidValidError,
    ValidTooLongError,
    VomsNotAllowedError,
    check_valid,
    check_voms,
)


class TestCheckValid:
    def test_valid_within_max_is_accepted(self) -> None:
        check_valid("24:00", max_valid="192:00")

    def test_valid_equal_to_max_is_accepted(self) -> None:
        check_valid("192:00", max_valid="192:00")

    def test_valid_over_max_is_rejected(self) -> None:
        with pytest.raises(ValidTooLongError):
            check_valid("193:00", max_valid="192:00")

    def test_minutes_component_pushes_valid_over_max(self) -> None:
        with pytest.raises(ValidTooLongError):
            check_valid("192:01", max_valid="192:00")

    @pytest.mark.parametrize(
        "valid",
        ["", "abc", "24", "24:60", "24:5", "-1:00", "24:00:00", "24: 00"],
    )
    def test_malformed_valid_is_rejected(self, valid: str) -> None:
        with pytest.raises(InvalidValidError):
            check_valid(valid, max_valid="192:00")


class TestCheckVoms:
    def test_allowed_voms_is_accepted(self) -> None:
        check_voms("atlas", allowed_voms=["atlas"])

    def test_voms_not_on_allowlist_is_rejected(self) -> None:
        with pytest.raises(VomsNotAllowedError):
            check_voms("cms", allowed_voms=["atlas"])

    def test_case_sensitive_match_only(self) -> None:
        with pytest.raises(VomsNotAllowedError):
            check_voms("ATLAS", allowed_voms=["atlas"])
