"""Codify `WITH (security_invoker = true)`, the rule a view over a row-level-secured table must obey.

New in this port: upstream (DelfinaCare/rls, MIT) documented nothing about views. A plain view runs
as its owner, bypassing row level security on every table it selects from entirely, since a view has
no rows or policies of its own to enforce; Postgres only let a view defer to the querying role's own
row level security starting with 15, behind this reloption
(https://www.postgresql.org/docs/current/sql-createview.html). Any view built over a table this
library protects must set it, or the view silently reintroduces exactly the leak row level security
exists to close.
"""


def security_invoker_view(name: str, definition: str) -> str:
    """The `CREATE VIEW ... WITH (security_invoker = true) AS ...` statement for one view.

    name: name of the view to create.
    definition: the view's `SELECT` body, without the `CREATE VIEW` wrapper.
    """
    return f"CREATE VIEW {name} WITH (security_invoker = true) AS {definition}"
