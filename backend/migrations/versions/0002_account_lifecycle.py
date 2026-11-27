"""Track disabled accounts, required password changes and new access-grant dates."""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"


def upgrade():
    op.add_column("users", sa.Column("disabled_at", sa.String(), nullable=True))
    op.add_column(
        "users",
        sa.Column(
            "password_change_required",
            sa.Boolean(),
            server_default=sa.false(),
            nullable=False,
        ),
    )
    op.add_column("case_access", sa.Column("created_at", sa.String(), nullable=True))


def downgrade():
    op.drop_column("case_access", "created_at")
    op.drop_column("users", "password_change_required")
    op.drop_column("users", "disabled_at")
