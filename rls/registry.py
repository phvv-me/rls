"""The process-wide list of metadatas `register()` has opted into row level security.

A table-name-only Alembic op (`op.apply_scoped_rls("table")`) carries no policies of its own, so at
invoke time it has to recover a table's declared policies and grant role from somewhere. Where the
inline `ApplyRlsOp` embeds them in the migration text, the scoped op reads them back from the live
model metadata `register()` opted in, found by searching this list for the one metadata that
declares the table. `register()` appends each base's metadata here once, and the scoped ops and
`verify_scoped_rls` read it back.
"""

from sqlalchemy.sql.schema import MetaData

from .policy import Policy

# every metadata `register()` opted into row level security, in registration order. A duplicate
# append is skipped so calling `register()` twice on one base never double-lists its metadata.
registered_metadatas: list[MetaData] = []


def remember_metadata(metadata: MetaData) -> None:
    """Record `metadata` as opted into row level security, ignoring a repeat registration.

    metadata: the declarative base's own metadata `register()` was called on.
    """
    if not any(metadata is existing for existing in registered_metadatas):
        registered_metadatas.append(metadata)


def metadata_for_table(table: str) -> MetaData:
    """The registered metadata that declares policies for `table`, for a table-name-only op to read.

    Raises `LookupError` naming the table when no registered metadata declares it, since a scoped op
    invoked for an unregistered table cannot recover the policies it needs and a silent skip would
    leave that table unprotected.

    table: the table name a scoped op was invoked for.
    """
    for metadata in registered_metadatas:
        if table in metadata.info.get("rls_policies", {}):
            return metadata
    raise LookupError(
        f"no registered metadata declares row level security policies for {table!r}; "
        "call `rls.register(base)` on the base that maps it before the migration runs"
    )


def declared_policies() -> dict[str, list[Policy]]:
    """Every `table -> policies` mapping across all registered metadatas, merged into one dict.

    The default policy set `verify_scoped_rls` checks against when a caller passes none of its own.
    """
    return {
        table: policies
        for metadata in registered_metadatas
        for table, policies in metadata.info.get("rls_policies", {}).items()
    }
