from alembic import context

from app.db import meta

connection = context.config.attributes["connection"]
context.configure(connection=connection, target_metadata=meta)
with context.begin_transaction():
    context.run_migrations()
