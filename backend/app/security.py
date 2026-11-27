import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import Depends, HTTPException, Security
from fastapi.security import APIKeyCookie
from sqlalchemy import delete, or_, select

from . import db
from .settings import SESSION_HOURS

COOKIE = "ttx_session"
session_cookie = APIKeyCookie(
    name=COOKIE,
    scheme_name="LocalSession",
    description="HTTP-only session cookie set by POST /api/v1/auth/login.",
    auto_error=False,
)


def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def password_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    derived = hashlib.scrypt(
        password.encode(), salt=salt, n=2**15, r=8, p=1, maxmem=64 * 1024**2
    )
    return f"{salt.hex()}:{derived.hex()}"


DUMMY_HASH = password_hash("invalid-session-password")


def verify_password(password, stored):
    try:
        salt = bytes.fromhex(stored.split(":", 1)[0])
    except ValueError:
        return False
    return hmac.compare_digest(stored, password_hash(password, salt))


def create_user(connection, username, password, role):
    return db.add(
        connection,
        db.users,
        username=username.lower(),
        password_hash=password_hash(password),
        role=role,
        created_at=db.utc(),
        disabled_at=None,
        password_change_required=False,
    )


def login(username, password):
    with db.transaction(write=False) as connection:
        user = db.one(connection, db.users, db.users.c.username == username.lower())
    valid = verify_password(password, user["password_hash"] if user else DUMMY_HASH)
    if not user or not valid or user["disabled_at"]:
        raise HTTPException(401, "Invalid credentials")
    token = secrets.token_urlsafe(32)
    with db.transaction() as connection:
        still_valid = lock_users(connection, user["id"]).get(user["id"])
        if (
            not still_valid
            or still_valid["disabled_at"]
            or not hmac.compare_digest(
                still_valid["password_hash"], user["password_hash"]
            )
        ):
            raise HTTPException(401, "Invalid credentials")
        connection.execute(
            delete(db.sessions).where(db.sessions.c.expires_at <= db.utc())
        )
        db.add(
            connection,
            db.sessions,
            id=digest(token),
            user_id=user["id"],
            expires_at=db.utc(datetime.now(UTC) + timedelta(hours=SESSION_HOURS)),
        )
        db.record(connection, user["username"], "signed_in")
    return still_valid, token


def session_user(token: Annotated[str | None, Security(session_cookie)]):
    if token:
        with db.transaction(write=False) as connection:
            session = db.one(
                connection,
                db.sessions,
                db.sessions.c.id == digest(token),
                db.sessions.c.expires_at > db.utc(),
            )
            if session:
                user = db.one(connection, db.users, db.users.c.id == session["user_id"])
                if user and not user["disabled_at"]:
                    return user
    raise HTTPException(401, "Sign in to continue")


SessionUser = Annotated[dict, Depends(session_user)]


def current(user: SessionUser):
    if user["password_change_required"]:
        raise HTTPException(403, "Change your temporary password to continue")
    return user


def lock_users(connection, *ids):
    rows = connection.execute(
        select(db.users)
        .where(db.users.c.id.in_(ids))
        .order_by(db.users.c.id)
        .with_for_update()
    ).mappings()
    return {row["id"]: dict(row) for row in rows}


def revoke_sessions(connection, user_id):
    connection.execute(delete(db.sessions).where(db.sessions.c.user_id == user_id))


def require_password(user, password):
    if (
        not user
        or user["disabled_at"]
        or not verify_password(password, user["password_hash"])
    ):
        raise HTTPException(403, "Current password is incorrect")


def admin(user):
    if user["role"] != "administrator":
        raise HTTPException(403, "Administrator access required")


def scope(user):
    if user["role"] == "administrator":
        return True
    shared = select(db.grants.c.case_id).where(db.grants.c.user_id == user["id"])
    return or_(db.cases.c.owner_id == user["id"], db.cases.c.id.in_(shared))


def require_case(connection, user, case_id):
    case = db.one(connection, db.cases, db.cases.c.id == case_id, scope(user))
    if not case:
        raise HTTPException(404, "Investigation not found")
    return case
