import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException, Request
from sqlalchemy import delete, or_, select

from . import db
from .settings import SESSION_HOURS

COOKIE = "ttx_session"


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
    return hmac.compare_digest(
        stored, password_hash(password, bytes.fromhex(stored.split(":")[0]))
    )


def create_user(connection, username, password, role):
    return db.add(
        connection,
        db.users,
        username=username.lower(),
        password_hash=password_hash(password),
        role=role,
        created_at=db.utc(),
    )


def login(username, password):
    with db.transaction(write=False) as connection:
        user = db.one(connection, db.users, db.users.c.username == username.lower())
    valid = verify_password(password, user["password_hash"] if user else DUMMY_HASH)
    if not user or not valid:
        raise HTTPException(401, "Invalid credentials")
    token = secrets.token_urlsafe(32)
    with db.transaction() as connection:
        still_valid = db.one(
            connection,
            db.users,
            db.users.c.id == user["id"],
            db.users.c.password_hash == user["password_hash"],
        )
        if not still_valid:
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


def current(request: Request):
    token = request.cookies.get(COOKIE)
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
                if user:
                    return user
    raise HTTPException(401, "Sign in to continue")


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
