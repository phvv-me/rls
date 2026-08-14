from .policy import Policy
from .predicate import Predicate


def crud(
    read: Predicate,
    *,
    write: Predicate,
    roles: tuple[str, ...] = ("public",),
) -> tuple[Policy, ...]:
    """Build one command-named read, insert, update, and delete policy."""
    return (
        Policy.select(read, roles=roles),
        Policy.insert(write, roles=roles),
        Policy.update(write, check=write, roles=roles),
        Policy.delete(write, roles=roles),
    )
