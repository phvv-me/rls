from enum import StrEnum
from enum import auto

from .rule import Rule


class Command(StrEnum):
    """PostgreSQL commands accepted by `CREATE POLICY`, each knowing its predicate shape."""

    all = auto()
    select = auto()
    insert = auto()
    update = auto()
    delete = auto()

    @property
    def sql(self) -> str:
        """Render the PostgreSQL command keyword."""
        return self.name.upper()

    @property
    def using(self) -> Rule:
        """The rule for the `USING` slot."""
        return Rule.forbidden if self is Command.insert else Rule.required

    @property
    def checking(self) -> Rule:
        """The rule for the `WITH CHECK` slot."""
        match self:
            case Command.insert | Command.update:
                return Rule.required
            case Command.all:
                return Rule.optional
            case _:
                return Rule.forbidden
