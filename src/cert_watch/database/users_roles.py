"""Repository for local users and roles (Plan 040)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from cert_watch.database.connection import _connect


@dataclass
class Role:
    id: str = ""
    name: str = ""
    email: str = ""
    description: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class User:
    id: str = ""
    username: str = ""
    email: str = ""
    password_hash: str = ""
    role_id: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class SqliteRoleRepository:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)

    def add(self, role: Role) -> str:
        role_id = role.id or str(uuid.uuid4())
        now = datetime.now(UTC).isoformat()
        with _connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO roles (id, name, email, description, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (role_id, role.name, role.email, role.description, now, now),
            )
            conn.commit()
        return role_id

    def get(self, role_id: str) -> Role | None:
        with _connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT id, name, email, description, created_at, updated_at "
                "FROM roles WHERE id = ?",
                (role_id,),
            ).fetchone()
        if row is None:
            return None
        return Role(
            id=row["id"],
            name=row["name"],
            email=row["email"],
            description=row["description"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    def get_by_name(self, name: str) -> Role | None:
        with _connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT id, name, email, description, created_at, updated_at "
                "FROM roles WHERE name = ?",
                (name,),
            ).fetchone()
        if row is None:
            return None
        return Role(
            id=row["id"],
            name=row["name"],
            email=row["email"],
            description=row["description"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    def list_all(self) -> list[Role]:
        with _connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT id, name, email, description, created_at, updated_at "
                "FROM roles ORDER BY name"
            ).fetchall()
        return [
            Role(
                id=r["id"],
                name=r["name"],
                email=r["email"],
                description=r["description"],
                created_at=datetime.fromisoformat(r["created_at"]),
                updated_at=datetime.fromisoformat(r["updated_at"]),
            )
            for r in rows
        ]

    def update(self, role: Role) -> None:
        now = datetime.now(UTC).isoformat()
        with _connect(self.db_path) as conn:
            conn.execute(
                "UPDATE roles SET name = ?, email = ?, description = ?, updated_at = ? "
                "WHERE id = ?",
                (role.name, role.email, role.description, now, role.id),
            )
            conn.commit()

    def delete(self, role_id: str) -> None:
        with _connect(self.db_path) as conn:
            conn.execute("DELETE FROM roles WHERE id = ?", (role_id,))
            conn.commit()


class SqliteUserRepository:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)

    def add(self, user: User) -> str:
        user_id = user.id or str(uuid.uuid4())
        now = datetime.now(UTC).isoformat()
        with _connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO users (id, username, email, password_hash, role_id, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (user_id, user.username, user.email, user.password_hash, user.role_id, now, now),
            )
            conn.commit()
        return user_id

    def get(self, user_id: str) -> User | None:
        with _connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT id, username, email, password_hash, role_id, created_at, updated_at "
                "FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
        if row is None:
            return None
        return User(
            id=row["id"],
            username=row["username"],
            email=row["email"],
            password_hash=row["password_hash"],
            role_id=row["role_id"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    def get_by_username(self, username: str) -> User | None:
        with _connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT id, username, email, password_hash, role_id, created_at, updated_at "
                "FROM users WHERE username = ?",
                (username,),
            ).fetchone()
        if row is None:
            return None
        return User(
            id=row["id"],
            username=row["username"],
            email=row["email"],
            password_hash=row["password_hash"],
            role_id=row["role_id"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    def list_all(self) -> list[User]:
        with _connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT id, username, email, password_hash, role_id, created_at, updated_at "
                "FROM users ORDER BY username"
            ).fetchall()
        return [
            User(
                id=r["id"],
                username=r["username"],
                email=r["email"],
                password_hash=r["password_hash"],
                role_id=r["role_id"],
                created_at=datetime.fromisoformat(r["created_at"]),
                updated_at=datetime.fromisoformat(r["updated_at"]),
            )
            for r in rows
        ]

    def update(self, user: User) -> None:
        now = datetime.now(UTC).isoformat()
        with _connect(self.db_path) as conn:
            conn.execute(
                "UPDATE users SET username = ?, email = ?, password_hash = ?, role_id = ?, updated_at = ? "
                "WHERE id = ?",
                (user.username, user.email, user.password_hash, user.role_id, now, user.id),
            )
            conn.commit()

    def delete(self, user_id: str) -> None:
        with _connect(self.db_path) as conn:
            conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
