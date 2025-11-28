"""add tls fingerprints table

Revision ID: 002
Revises: 001
Create Date: 2024-01-15 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy import text

# revision identifiers, used by Alembic.
revision = '002'
down_revision = '001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    
    tls_fingerprints_exists = conn.execute(
        text("SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'tls_fingerprints')")
    ).scalar()
    
    if not tls_fingerprints_exists:
        op.create_table(
            'tls_fingerprints',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('fingerprint', sa.String(), nullable=False),
            sa.Column('fingerprint_hash', sa.String(), nullable=False),
            sa.Column('description', sa.Text(), nullable=True),
            sa.Column('is_whitelisted', sa.Boolean(), nullable=True, server_default='false'),
            sa.Column('is_blacklisted', sa.Boolean(), nullable=True, server_default='false'),
            sa.Column('threat_level', sa.String(), nullable=True, server_default='unknown'),
            sa.Column('first_seen', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
            sa.Column('last_seen', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
            sa.Column('request_count', sa.Integer(), nullable=True, server_default='0'),
            sa.Column('blocked_count', sa.Integer(), nullable=True, server_default='0'),
            sa.Column('fingerprint_metadata', sa.Text(), nullable=True),
            sa.PrimaryKeyConstraint('id')
        )
        
        index_names = [
            'ix_tls_fingerprints_id',
            'ix_tls_fingerprints_fingerprint',
            'ix_tls_fingerprints_fingerprint_hash',
            'ix_tls_fingerprints_is_whitelisted',
            'ix_tls_fingerprints_is_blacklisted'
        ]
        
        for index_name in index_names:
            index_exists = conn.execute(
                text(f"SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = '{index_name}')")
            ).scalar()
            if not index_exists:
                if index_name == 'ix_tls_fingerprints_id':
                    op.create_index(index_name, 'tls_fingerprints', ['id'], unique=False)
                elif index_name == 'ix_tls_fingerprints_fingerprint':
                    op.create_index(index_name, 'tls_fingerprints', ['fingerprint'], unique=True)
                elif index_name == 'ix_tls_fingerprints_fingerprint_hash':
                    op.create_index(index_name, 'tls_fingerprints', ['fingerprint_hash'], unique=True)
                elif index_name == 'ix_tls_fingerprints_is_whitelisted':
                    op.create_index(index_name, 'tls_fingerprints', ['is_whitelisted'], unique=False)
                elif index_name == 'ix_tls_fingerprints_is_blacklisted':
                    op.create_index(index_name, 'tls_fingerprints', ['is_blacklisted'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_tls_fingerprints_is_blacklisted'), table_name='tls_fingerprints')
    op.drop_index(op.f('ix_tls_fingerprints_is_whitelisted'), table_name='tls_fingerprints')
    op.drop_index(op.f('ix_tls_fingerprints_fingerprint_hash'), table_name='tls_fingerprints')
    op.drop_index(op.f('ix_tls_fingerprints_fingerprint'), table_name='tls_fingerprints')
    op.drop_index(op.f('ix_tls_fingerprints_id'), table_name='tls_fingerprints')
    op.drop_table('tls_fingerprints')

