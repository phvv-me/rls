# rlsalchemy

Declarative PostgreSQL row level security for SQLAlchemy 2.1 and Alembic 1.18.

Models own policy expressions. A typed context model derives every setting name, SQL cast,
and prefix from one class. SQLAlchemy table metadata carries the compiled declaration.
Alembic compares that declaration with PostgreSQL and writes one reversible operation for
the complete table state. Sessions bind request context through the standard `Session.info`
mapping and `SessionEvents.after_begin`.

## Context

Declare the transaction-local settings once as a typed model. Field names become setting
names, annotations derive the casts, and the prefix snake-cases from the class name unless
passed explicitly. Class access projects a field to its policy-side expression, so the
predicate and the bound value can never drift apart.

```python
import uuid

import rls
from patos import FrozenModel


class ScopeTable(FrozenModel):
    read: frozenset[uuid.UUID] = frozenset()
    write: frozenset[uuid.UUID] = frozenset()


class User(rls.Context, prefix="app"):
    scopes: ScopeTable = ScopeTable()
```

## Models

Declare `__rls__` on a mapped class and build a `Catalog` after all models import. An
inherited declaration protects every concrete subclass, which keeps shared tenant rules in
one mixin. Every mapped table must declare policies or opt out with the singleton
`rls.Open()`, so an unprotected table is a decision, never an accident.

```python
import rls
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Item(Base):
    __tablename__ = "item"

    id: Mapped[int] = mapped_column(primary_key=True)
    scopes: Mapped[list[uuid.UUID]] = mapped_column(ARRAY(sa.Uuid()))

    @classmethod
    def __rls__(cls) -> tuple[rls.Policy, ...]:
        row = sa.func.to_jsonb(cls.scopes)
        readable = row.op("<@")(User.scopes["read"])
        writable = row.op("<@")(User.scopes["write"])
        return rls.crud(readable, writable, name="scope")


catalog = rls.Catalog(Base.registry)
```

`Catalog` is a closed set of mapped tables and policy declarations. It is deliberately not
the self-registering implementation pattern provided by `patos.Registry`.

`rls.crud` produces separate select, insert, update, and delete policies. Individual policy
constructors (`Policy.select`, `Policy.insert`, `Policy.update`, `Policy.delete`,
`Policy.for_all`) cover tables that need a different shape, multiple roles, or restrictive
composition.

## Sessions

No custom session class is required. Pass the context instance's `info()` as standard
session information.

```python
from sqlalchemy.ext.asyncio import async_sessionmaker


sessions = async_sessionmaker(engine)

user = User(
    scopes=ScopeTable(
        read=frozenset({account}),
        write=frozenset({account}),
    )
)
async with sessions(info=user.info()) as session:
    async with session.begin():
        rows = await session.scalars(sa.select(Item))
```

The package writes every value with SQLAlchemy `set_config` expressions and transaction-local
scope, serialized once per context instance. A pooled connection cannot retain context after
commit or rollback. Scalars, dates, UUIDs, tuples, and `None` are supported.

## Alembic

The installed package exposes an Alembic 1.18 plugin. Enable it beside the built-in plugins.

```python
context.configure(
    connection=connection,
    target_metadata=Base.metadata,
    autogenerate_plugins=["alembic.autogenerate.*", "rls"],
)
```

Autogenerate reads all managed tables in one joined catalog query. Drift produces one
typed `AlterRLSOp` carrying complete before and after `rls.RLSState` values, so
downgrade is the same operation with the states reversed. The snapshot includes enable and
force flags as well as policies, so a partially configured live table also reverses exactly.
The renderer stores each state through Pydantic structured data. As with every Alembic
autogenerate candidate, applications may replace a large compiled snapshot with equivalent
migration-local SQLAlchemy expressions before accepting the revision.

## Verification

Applications can verify the live database without generating a migration.

```python
violations = catalog.verify(connection)
assert not violations
```

Verification checks enable and force flags, every declared policy, commands, permissive or
restrictive mode, target roles, predicates, and undeclared live policies. Policy comparison
uses a PostgreSQL AST and preserves casts that can change behavior, folding deparser noise
through SQLGlot's leaves-first tree replacement. `CompiledPolicy` then uses frozen value
equality over the canonical result. Managed tables with undeclared live row security are
reported too.

Applications without Alembic can call `catalog.create_all(connection)` inside their own
transaction. Every emitted schema statement is a typed SQLAlchemy `ExecutableDDLElement`
with dialect-managed identifier quoting.

## Auditing

rlsalchemy owns declaration, installation, and drift detection. For posture reports, lint
rules, isolation proofs, and CI gating over the live database, pair it with
[pgrls](https://github.com/pgrls/pgrls), which reads the same catalog state this package
writes.
