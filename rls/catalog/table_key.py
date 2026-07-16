import sqlalchemy as sa
from patos import FrozenModel
from sqlalchemy import Table
from sqlalchemy.engine import Connection


class TableKey(FrozenModel):
    """Schema-qualified identity inside the reflected catalog."""

    schema_name: str
    table_name: str

    @classmethod
    def of(cls, table: Table, connection: Connection) -> "TableKey":
        """Resolve a table's schema-qualified identity."""
        schema = connection.dialect.default_schema_name or "public"
        return cls(schema_name=table.schema or schema, table_name=table.name)

    def table(self) -> Table:
        """Build a lightweight table for dialect-safe DDL compilation."""
        return sa.Table(self.table_name, sa.MetaData(), schema=self.schema_name)
