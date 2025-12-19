import os
from typing import AsyncGenerator, Generator
from contextlib import asynccontextmanager, contextmanager

from sqlalchemy import create_engine, MetaData
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, AsyncEngine
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from sqlalchemy.pool import NullPool

from config import settings
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Database URL configuration
DATABASE_URL = settings.get_database_url()
ASYNC_DATABASE_URL = settings.get_async_database_url()

# Create async engine
async_engine: AsyncEngine = create_async_engine(
    ASYNC_DATABASE_URL,
    echo=settings.SQL_ECHO,
    future=True,
    pool_pre_ping=True,
    pool_recycle=3600,
    pool_size=settings.DATABASE_POOL_SIZE,
    max_overflow=settings.DATABASE_MAX_OVERFLOW,
)

# Create sync engine (for migrations and sync operations)
sync_engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=3600,
    pool_size=settings.DATABASE_POOL_SIZE,
    max_overflow=settings.DATABASE_MAX_OVERFLOW,
)

# Session factories
AsyncSessionLocal = sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

SyncSessionLocal = sessionmaker(
    bind=sync_engine,
    autocommit=False,
    autoflush=False,
)

# Base class for models
Base = declarative_base()
metadata = Base.metadata

# Dependency to get async DB session
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Get async database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception as e:
            await session.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            await session.close()

# Dependency to get sync DB session
@contextmanager
def get_sync_db() -> Generator[Session, None, None]:
    """Get sync database session."""
    db = SyncSessionLocal()
    try:
        yield db
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Database error: {e}")
        raise
    finally:
        db.close()

# For FastAPI Depends
async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Get async database session for FastAPI dependency injection."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()

# Initialize database (create tables)
async def init_db() -> None:
    """Initialize the database (create tables)."""
    async with async_engine.begin() as conn:
        await conn.run_sync(metadata.create_all)
    logger.info("Database tables created successfully")

# Drop all tables (for testing)
async def drop_db() -> None:
    """Drop all database tables (for testing)."""
    async with async_engine.begin() as conn:
        await conn.run_sync(metadata.drop_all)
    logger.info("Dropped all database tables")

# Import models to ensure they are registered with SQLAlchemy
from ..models.user import User, APIToken  # noqa
from ..models.incident import Incident, IOC, AnalysisResult  # noqa
from ..models.threat_intel import ThreatIntelCache  # noqa
