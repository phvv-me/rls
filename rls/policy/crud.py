from .policy import Policy
from .predicate import Predicate


def crud(
    read: Predicate,
    write: Predicate,
    name: str = "scope",
    roles: tuple[str, ...] = ("public",),
) -> tuple[Policy, ...]:
    """Build stable read, insert, update, and delete policies."""
    return (
        Policy.select(f"{name}_read", read, roles=roles),
        Policy.insert(f"{name}_insert", write, roles=roles),
        Policy.update(f"{name}_update", write, write, roles=roles),
        Policy.delete(f"{name}_delete", write, roles=roles),
    )
