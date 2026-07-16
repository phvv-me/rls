from enum import StrEnum
from enum import auto
from typing import TYPE_CHECKING

from .predicate import Predicate

if TYPE_CHECKING:
    from .command import Command


class Rule(StrEnum):
    """Whether a policy command takes a predicate slot."""

    required = auto()
    forbidden = auto()
    optional = auto()

    def check(self, command: "Command", slot: str, predicate: Predicate | None) -> None:
        """Reject a predicate that violates this rule."""
        if self is Rule.required and predicate is None:
            raise ValueError(f"{command.sql} requires {slot}")
        if self is Rule.forbidden and predicate is not None:
            raise ValueError(f"{command.sql} forbids {slot}")
