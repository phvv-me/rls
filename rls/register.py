"""Wire a declarative base's mapped classes into their own row-level-security registry.

Ported from DelfinaCare/rls (MIT, https://github.com/DelfinaCare/rls)'s `register.base_wrapper`,
which listened for `Mapper` construction globally and wrote into whichever `Base` had opted in via
`metadata.info["rls_policies"]`. This port keeps that opt-in gate (so more than one
`DeclarativeBase`/`SQLModel` registry can coexist in one process without cross-registering each
other) and additionally accepts `__rls_policies__` as a zero-argument callable, not only a plain
list: a callable can reach `cls.__table__.c`, the table SQLAlchemy has by the time this
mapper-construction hook fires, letting a policy reference a model's own mapped columns instead of
upstream's bare `sqlalchemy.column("name")` stand-ins.
"""

from sqlalchemy import Table
from sqlalchemy import event
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import Mapper

from .policy import Policy


def _declared_policies(class_: type) -> list[Policy] | None:
    """Read one mapped class's own declared policies, calling them if declared as a classmethod.

    Returning `None` rather than an empty list distinguishes "this class declares nothing" (no
    `__rls_policies__` attribute at all) from "this class opted in with zero policies"; both leave
    the registry untouched either way, but only the first is worth a fast exit before the callable
    check.

    class_: the mapped class to read `__rls_policies__` from, if it declares one.
    """
    declare = getattr(class_, "__rls_policies__", None)
    if declare is None:
        return None
    return declare() if callable(declare) else declare


@event.listens_for(Mapper, "after_mapper_constructed")
def _register_declared_policies(mapper: Mapper, class_: type) -> None:
    """Read a freshly mapped class's declared policies into its own metadata's registry.

    Fires for every mapped class in the process, scoped by checking the mapped table's own
    metadata rather than a hardcoded base, so this one global listener serves every registry
    `register()` has opted in without needing a listener per base. The table's metadata, not
    `class_.metadata`, is the source of truth here: an imperatively mapped class
    (`registry.map_imperatively(cls, table)`, the shape a read-only view like a SQL `VIEW` often
    uses) carries no `metadata` attribute of its own at all, only its mapped `Table` does. A
    metadata `register()` has not yet touched (no `"rls_policies"` key in `metadata.info`) is left
    alone, and so is a class with no `__rls_policies__` of its own.

    mapper: the mapper SQLAlchemy just finished constructing.
    class_: the mapped class the mapper belongs to.
    """
    local_table = mapper.local_table
    assert isinstance(local_table, Table), "a mapped class's local_table is always its own Table"
    metadata = local_table.metadata
    if "rls_policies" not in metadata.info:
        return
    policies = _declared_policies(class_)
    if policies is None:
        return
    metadata.info["rls_policies"][local_table.name] = policies


def register(base: type[DeclarativeBase], grant_role: str | None = None) -> type[DeclarativeBase]:
    """Opt `base` into row level security, then read every class it has already mapped.

    Call once per declarative base during application setup, before Alembic autogenerate or
    `create_policies` runs against it. A class mapped after this call is caught by the
    `after_mapper_constructed` listener instead; both paths write into the same
    `base.metadata.info["rls_policies"]` dict, so declaration order relative to `register()` never
    matters.

    base: the `DeclarativeBase` (or `SQLModel`) subclass whose registry to scan.
    grant_role: role every protected table should `GRANT` CRUD to, stored on the metadata for
        `create_policies` and the Alembic comparator to read; omit when nothing should be granted.
    """
    base.metadata.info.setdefault("rls_policies", {})
    if grant_role is not None:
        base.metadata.info["rls_grant_role"] = grant_role
    for mapper in base.registry.mappers:
        _register_declared_policies(mapper, mapper.class_)
    return base
