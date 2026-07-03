# rls

Declarative PostgreSQL row level security for SQLAlchemy and Alembic.

A fork of [DelfinaCare/rls](https://github.com/DelfinaCare/rls) (MIT), reworked from the ground up
while keeping its public spirit: a model states its own row level security policies as
`__rls_policies__`, and Alembic autogenerate creates, diffs, and drops them for you. See
[Changes from upstream](#changes-from-upstream) for what moved and why.

---

## Installation

```bash
pip install rls
```

## Usage

### Defining policies

Attach `__rls_policies__` to any SQLAlchemy mapped class to declare which policies apply to it. A
policy names exactly one command, `select`, `insert`, `update`, or `delete`, never `ALL`: a `FOR
ALL` policy's `USING` clause is also OR-ed into a table's `SELECT` visibility by Postgres, so a
narrower write predicate would leak past a table's read predicate.

```python
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.orm import DeclarativeBase, relationship

import rls


class Base(DeclarativeBase):
    pass


class Item(Base):
    __tablename__ = "items"

    id = Column(Integer, primary_key=True)
    title = Column(String)
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))

    def __rls_policies__(self=None) -> list[rls.Policy]:
        owner = rls.current_setting("account_id", Integer(), prefix="app")
        mine = Item.owner_id == owner
        return [
            rls.Policy(name="items_read", command=rls.Command.select, using=mine),
            rls.Policy(name="items_insert", command=rls.Command.insert, check=mine),
            rls.Policy(name="items_update", command=rls.Command.update, using=mine, check=mine),
            rls.Policy(name="items_delete", command=rls.Command.delete, using=mine),
        ]
```

`__rls_policies__` may be a plain list (built from bare, table-unqualified `sqlalchemy.column()`
stand-ins, the shape upstream used) or a zero-argument callable, as above, so a policy can reference
a model's own mapped columns (`Item.owner_id`) instead: the callable form runs once the table
actually exists, after SQLAlchemy has finished mapping the class.

#### `current_setting`

`rls.current_setting(name, type_, prefix)` reads a Postgres session variable (`SET LOCAL
<prefix>.<name>`) as a scalar-subquery `InitPlan`, evaluated once per query rather than once per
row. The GUC namespace is a parameter here, never a module constant, so more than one registry can
share a process without colliding.

#### Registering a declarative base

```python
import rls

rls.register(Base)
```

Call this once per declarative base during application setup, before Alembic autogenerate runs
against it or before calling `rls.create_policies` directly. Pass `grant_role="my_app_role"` to also
have every protected table `GRANT SELECT, INSERT, UPDATE, DELETE` to that role.

#### Alembic

Importing `rls` registers its autogenerate operations, comparator, and renderers as a side effect;
just make sure `rls` (and `rls.register(Base)`) is imported before `env.py` runs autogenerate:

```python
import rls

rls.register(Base)
target_metadata = Base.metadata
```

Generate a revision and run `alembic upgrade head` as normal, policies are created, diffed, or
dropped automatically. A table with no `FORCE ROW LEVEL SECURITY` (or no row security at all) gets
the whole-table `op.apply_rls(...)` bootstrap; an already-protected table gets a per-policy diff
instead, `op.create_rls_policy(...)`/`op.drop_rls_policy(...)`, so a single changed clause never
reapplies an entire table's policy set.

If you are not using Alembic, call `rls.create_policies(metadata, connection)` directly after
`metadata.create_all()`.

---

### Using policies at runtime

Policies are enforced through `RlsSession`, a drop-in replacement for SQLAlchemy's `Session`. Supply
a Pydantic context object whose fields match the names your policies read via `current_setting`,
plus a bound engine:

```python
from pydantic import BaseModel

from rls import RlsSession


class MyContext(BaseModel):
    account_id: int


session = RlsSession(context=MyContext(account_id=1), guc_prefix="app", bind=engine)
rows = session.execute(text("SELECT * FROM items")).fetchall()
```

`guc_prefix` (default `"rls"`) must match the prefix your policies were built with. There is no
bypass branch baked into any policy by default; a policy that wants an escape hatch composes
`rls.bypass_clause(prefix)` into its own `using`/`check` expression, and `session.bypass_rls()`
opens a block where that flag reads `true`:

```python
with session.bypass_rls() as session:
    rows = session.execute(text("SELECT * FROM items")).fetchall()
```

#### `RlsSessioner`

For an app that builds a session per request or operation, `RlsSessioner` wraps a `sessionmaker`
(`class_=RlsSession`) and a `ContextGetter` subclass into a ready-to-use session factory. It takes
no framework dependency; wrap it in your own framework's dependency-injection mechanism (FastAPI
`Depends`, a Flask decorator, or a bare `with` block) as needed.

```python
from sqlalchemy.orm import sessionmaker

from rls import ContextGetter, RlsSession, RlsSessioner


class MyContextGetter(ContextGetter):
    def get_context(self, *args, **kwargs) -> MyContext:
        return MyContext(account_id=kwargs["account_id"])


session_maker = sessionmaker(class_=RlsSession, bind=engine)
sessioner = RlsSessioner(sessionmaker=session_maker, context_getter=MyContextGetter())

with sessioner(account_id=22) as session:
    rows = session.execute(text("SELECT * FROM items")).fetchall()
```

---

### Views over a protected table

A plain view runs as its owner, bypassing row level security on every table it selects from
entirely; a view carries no rows or policies of its own to enforce. Postgres only lets a view defer
to the querying role's own row level security starting with version 15, behind the
`security_invoker` reloption. Any view over a table this library protects must set it:

```python
import rls

statement = rls.security_invoker_view("items_summary", "SELECT owner_id, count(*) FROM items GROUP BY owner_id")
```

Without `WITH (security_invoker = true)`, the view silently reintroduces exactly the leak row level
security exists to close.

---

### Verifying the live schema

`rls.verify_rls(connection, expected, declared)` reads `pg_class`/`pg_policies` back and reports
every way the live schema disagrees with what is declared, independent of any pending migration, a
missing policy, one with a drifted clause, or a table that lost `FORCE`:

```python
violations = rls.verify_rls(connection, expected={"items"}, declared=Base.metadata.info["rls_policies"])
assert violations == []
```

---

## Changes from upstream

- **Generic GUC namespace.** `current_setting`/`RlsSession` take the prefix as a parameter, never a
  hardcoded `rls.` module constant, so more than one registry can share a process.
- **No framework dependency.** No `starlette`/FastAPI import anywhere in the library; `RlsSessioner`
  is framework-agnostic, wrap it in your own framework's DI as needed.
- **`FORCE ROW LEVEL SECURITY` on every path.** Upstream only forced row security on its direct
  `create_policies()` path, never through Alembic; without `FORCE`, the table's own owning role
  still bypasses every policy. This fork emits it everywhere.
- **One command per policy, never `FOR ALL`.** A `FOR ALL` policy's `USING` clause is also OR-ed
  into `SELECT` visibility by Postgres, letting a write predicate leak into read visibility.
- **No default bypass escape.** Upstream's `Policy.allow_bypass_rls=True` stitched a matching `OR`
  branch into every generated policy whether wanted or not. `rls.bypass_clause` is available but
  opt-in, a policy composes it explicitly.
- **`sqlglot`-based clause comparison.** The Alembic comparator parses both the compiled policy
  expression and the catalog's deparsed `qual`/`with_check` into ASTs (via `sqlglot`), folds casts,
  parens, `= ANY (ARRAY[...])` vs `IN (...)`, and self-table qualification, then compares the
  canonicalized SQL text, replacing a regex-based text fold.
- **`ops/` as a folder**, not one file: `operations.py` (the `MigrateOperation` classes),
  `implementations.py` (their DDL), `comparator.py` (the autogenerate diff), `renderer.py` (turning
  a queued op back into migration source).
- **Every op is self-contained.** `ApplyRlsOp`/`DropRlsOp`/`CreatePolicyOp`/`DropPolicyOp` all carry
  their compiled policies inline; nothing in the Alembic layer reads a global metadata reference at
  migration-run time.
- **Pydantic models.** `Policy`, `CompiledPolicy`, `RlsSessioner`, and `AsyncRlsSessioner` are frozen
  `pydantic.BaseModel`s rather than dataclasses or plain classes.
- **`verify_rls`.** New: checks the live catalog against the declared registry directly, independent
  of any pending migration, for a CI gate or a startup guard.
- **`security_invoker_view`.** New: documents and codifies the `WITH (security_invoker = true)` rule
  a view over a protected table must follow.

## LICENSE

[MIT](./LICENSE)
