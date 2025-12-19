"""Pytest configuration and fixtures."""
import asyncio
import os
import pytest
from typing import AsyncGenerator, Generator
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from src.db.database import Base, get_db, async_engine, async_session_maker
from src.main import create_application

# Use SQLite for testing
TEST_DB_PATH = "test.db"
TEST_DATABASE_URL = f"sqlite+aiosqlite:///{TEST_DB_PATH}"

# Create test engine and session
TEST_ASYNC_ENGINE = create_async_engine(
    TEST_DATABASE_URL,
    echo=True,
    future=True,
    connect_args={"check_same_thread": False}  # Required for SQLite
)

TestingSessionLocal = sessionmaker(
    TEST_ASYNC_ENGINE, class_=AsyncSession, expire_on_commit=False
)

# Override the get_db dependency
async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
    """Override the get_db dependency for testing."""
    async with TestingSessionLocal() as session:
        yield session

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="session")
async def test_app() -> FastAPI:
    """Create a test FastAPI application."""
    # Clean up any existing test database
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)
        
    app = create_application()
    
    # Override dependencies
    app.dependency_overrides[get_db] = override_get_db
    
    return app

@pytest.fixture(scope="session")
async def test_client(test_app: FastAPI) -> TestClient:
    """Create a test client for the FastAPI application."""
    from fastapi.testclient import TestClient
    return TestClient(test_app)

@pytest.fixture(scope="session")
async def setup_test_database():
    """Set up the test database with all tables."""
    # Create all tables
    async with TEST_ASYNC_ENGINE.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    yield  # This is where the testing happens
    
    # Clean up
    async with TEST_ASYNC_ENGINE.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    
    # Remove the test database file
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)
    
    # Dispose the engine
    await TEST_ASYNC_ENGINE.dispose()

@pytest.fixture(scope="function")
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Create a new database session for a test."""
    async with TestingSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

# Fixtures for test data
@pytest.fixture
def test_user_data():
    return {
        "email": "test@example.com",
        "password": "testpassword123",
        "full_name": "Test User"
    }

@pytest.fixture
async def create_test_user(db_session: AsyncSession, test_user_data: dict):
    """Create a test user in the database."""
    from src.models.user import User
    from src.core.security import get_password_hash
    
    user = User(
        email=test_user_data["email"],
        hashed_password=get_password_hash(test_user_data["password"]),
        full_name=test_user_data["full_name"],
        is_active=True,
    )
    
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user

@pytest.fixture
async def authenticated_client(test_client: TestClient, create_test_user, test_user_data: dict):
    """Return an authenticated test client."""
    # Login to get the token
    login_data = {
        "username": test_user_data["email"],
        "password": test_user_data["password"]
    }
    
    response = test_client.post("/api/v1/auth/login", data=login_data)
    assert response.status_code == 200
    token = response.json()["access_token"]
    
    # Set the authorization header
    test_client.headers.update({"Authorization": f"Bearer {token}"})
    return test_client
