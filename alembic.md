# Alembic integration

This is a guide to how `rls` plugs into Alembic; see the [README](./README.md) for the declarative
`__rls_policies__` API most callers only ever need.

## Setting up Alembic

Importing `rls` registers its operations, comparator, and renderers as a side effect. In your
`env.py`, import `rls` and call `register` on your declarative base before autogenerate runs:

```python
import rls

rls.register(Base)
target_metadata = Base.metadata
```

## Operations available in a revision

Four custom operations are available on the `op` proxy inside a migration:

- `op.apply_rls(table, policies, grant_role=None)`: force row level security on `table` and create
  every policy in `policies`, in order. The whole-table bootstrap, used for a brand-new protected
  table or one whose `FORCE`/`ENABLE` was stripped outside a migration.
- `op.drop_rls(table, policies, grant_role=None)`: the reverse, dropping every policy in `policies`
  and disabling row level security on `table`.
- `op.create_rls_policy(table, policy)`: create or replace one named policy on an already-protected
  table. Idempotent, implemented as drop-if-exists then create.
- `op.drop_rls_policy(table, policy)`: drop one named policy from `table`.

`policies`/`policy` are `list[rls.CompiledPolicy]`/`rls.CompiledPolicy`, the plain-text compiled
form (see `rls.compile_policy`), not the live `rls.Policy` a model declares. `typing.cast(rls.ops.RLSOp,
op)` gives fully-typed access to all four from inside a migration file, no `# type: ignore` needed.

```python
from alembic import op
import rls
import typing

typing.cast(rls.ops.RLSOp, op).apply_rls(
    "accounts",
    [rls.CompiledPolicy(name="accounts_select", command=rls.Command.select, using="true")],
)
```

`autogenerate` picks a granularity automatically: a table missing `FORCE`/`ENABLE` gets the
whole-table `apply_rls`/`drop_rls` bootstrap; an already-protected table with only some policies
drifted gets the fine-grained `create_rls_policy`/`drop_rls_policy` instead, so a single changed
clause never reapplies an entire table's policy set. Automatically generated migrations should
still be read before running `alembic upgrade head`.

## Limitations

- These four operations are not picked up by static type checkers on the bare `op` proxy; use
  `typing.cast(rls.ops.RLSOp, op)` to get typed access inside a migration file.
