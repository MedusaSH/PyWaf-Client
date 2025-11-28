"""initial migration

Revision ID: 001
Revises: 
Create Date: 2024-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy import text

# revision identifiers, used by Alembic.
revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    
    threatlevel_exists = conn.execute(
        text("SELECT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'threatlevel')")
    ).scalar()
    
    if not threatlevel_exists:
        op.execute(text("CREATE TYPE threatlevel AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')"))
    
    threatlevel_enum = postgresql.ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL', name='threatlevel', create_type=False)
    
    iplisttype_exists = conn.execute(
        text("SELECT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'iplisttype')")
    ).scalar()
    
    if not iplisttype_exists:
        op.execute(text("CREATE TYPE iplisttype AS ENUM ('WHITELIST', 'BLACKLIST')"))
    
    iplisttype_enum = postgresql.ENUM('WHITELIST', 'BLACKLIST', name='iplisttype', create_type=False)
    
    security_events_exists = conn.execute(
        text("SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'security_events')")
    ).scalar()
    
    if not security_events_exists:
        op.create_table(
            'security_events',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('ip_address', sa.String(), nullable=True),
            sa.Column('endpoint', sa.String(), nullable=True),
            sa.Column('method', sa.String(), nullable=True),
            sa.Column('threat_type', sa.String(), nullable=True),
            sa.Column('threat_level', threatlevel_enum, nullable=True),
            sa.Column('payload', postgresql.JSON(astext_type=sa.Text()), nullable=True),
            sa.Column('user_agent', sa.String(), nullable=True),
            sa.Column('blocked', sa.Integer(), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
            sa.PrimaryKeyConstraint('id')
        )
        op.create_index(op.f('ix_security_events_id'), 'security_events', ['id'], unique=False)
        op.create_index(op.f('ix_security_events_ip_address'), 'security_events', ['ip_address'], unique=False)
        op.create_index(op.f('ix_security_events_endpoint'), 'security_events', ['endpoint'], unique=False)
        op.create_index(op.f('ix_security_events_threat_type'), 'security_events', ['threat_type'], unique=False)
        op.create_index(op.f('ix_security_events_threat_level'), 'security_events', ['threat_level'], unique=False)
        op.create_index(op.f('ix_security_events_created_at'), 'security_events', ['created_at'], unique=False)

    ip_lists_exists = conn.execute(
        text("SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'ip_lists')")
    ).scalar()
    
    if not ip_lists_exists:
        op.create_table(
            'ip_lists',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('ip_address', sa.String(), nullable=True),
            sa.Column('list_type', iplisttype_enum, nullable=True),
            sa.Column('reason', sa.String(), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
            sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
            sa.PrimaryKeyConstraint('id')
        )
        op.create_index(op.f('ix_ip_lists_id'), 'ip_lists', ['id'], unique=False)
        op.create_index(op.f('ix_ip_lists_ip_address'), 'ip_lists', ['ip_address'], unique=True)
        op.create_index(op.f('ix_ip_lists_list_type'), 'ip_lists', ['list_type'], unique=False)

    rules_exists = conn.execute(
        text("SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'rules')")
    ).scalar()
    
    if not rules_exists:
        op.create_table(
            'rules',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('name', sa.String(), nullable=True),
            sa.Column('enabled', sa.Boolean(), nullable=True),
            sa.Column('pattern', sa.String(), nullable=True),
            sa.Column('threat_type', sa.String(), nullable=True),
            sa.Column('sensitivity', sa.String(), nullable=True),
            sa.Column('custom_config', postgresql.JSON(astext_type=sa.Text()), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
            sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
            sa.PrimaryKeyConstraint('id')
        )
        op.create_index(op.f('ix_rules_id'), 'rules', ['id'], unique=False)
        op.create_index(op.f('ix_rules_name'), 'rules', ['name'], unique=True)
        op.create_index(op.f('ix_rules_threat_type'), 'rules', ['threat_type'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_rules_threat_type'), table_name='rules')
    op.drop_index(op.f('ix_rules_name'), table_name='rules')
    op.drop_index(op.f('ix_rules_id'), table_name='rules')
    op.drop_table('rules')
    op.drop_index(op.f('ix_ip_lists_list_type'), table_name='ip_lists')
    op.drop_index(op.f('ix_ip_lists_ip_address'), table_name='ip_lists')
    op.drop_index(op.f('ix_ip_lists_id'), table_name='ip_lists')
    op.drop_table('ip_lists')
    op.drop_index(op.f('ix_security_events_created_at'), table_name='security_events')
    op.drop_index(op.f('ix_security_events_threat_level'), table_name='security_events')
    op.drop_index(op.f('ix_security_events_threat_type'), table_name='security_events')
    op.drop_index(op.f('ix_security_events_endpoint'), table_name='security_events')
    op.drop_index(op.f('ix_security_events_ip_address'), table_name='security_events')
    op.drop_index(op.f('ix_security_events_id'), table_name='security_events')
    op.drop_table('security_events')

