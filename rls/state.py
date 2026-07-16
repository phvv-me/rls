from typing import Self

from patos import FrozenModel

from .policy import CompiledPolicy
from .policy import Policy


class RLSState(FrozenModel):
    """One table's declared or reflected row security state."""

    enabled: bool = True
    forced: bool = True
    policies: tuple[CompiledPolicy, ...] = ()

    @classmethod
    def declared(cls, policies: tuple[Policy, ...]) -> Self:
        """Compile policies into an enabled and forced table state."""
        return cls(policies=tuple(policy.compile() for policy in policies))

    @property
    def exists(self) -> bool:
        """Whether the table has any row security state."""
        return self.enabled or self.forced or bool(self.policies)

    def diff(self, live: Self, table: str) -> tuple[str, ...]:
        """Report every way `live` differs from this declared state."""
        drifted: list[str] = []
        if self.enabled is not live.enabled:
            drifted.append(f"{table} row level security should be enabled={self.enabled}")
        if self.forced is not live.forced:
            drifted.append(f"{table} row level security should be forced={self.forced}")

        reflected = {policy.name: policy for policy in live.policies}
        for policy in self.policies:
            if policy.name not in reflected:
                drifted.append(f"{table} is missing policy {policy.name}")
            elif not policy.matches(reflected[policy.name], table):
                drifted.append(f"{table} policy {policy.name} has drifted")

        declared = {policy.name for policy in self.policies}
        drifted.extend(
            f"{table} has undeclared policy {name}" for name in sorted(reflected.keys() - declared)
        )
        return tuple(drifted)

    def matches(self, live: Self, table: str) -> bool:
        """Whether `live` exactly matches this declared state."""
        return not self.diff(live, table)
