"""Schema migrations package.

Forward-only, idempotent migrations tracked in a `schema_version` table.
Each migration is a callable `(conn) -> None` registered with an id and
a short description. The runner applies any migration not yet recorded.
"""
