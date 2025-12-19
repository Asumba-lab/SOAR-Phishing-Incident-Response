"""Script to set up the test database."""
import asyncio
import os
from sqlalchemy.ext.asyncio import create_async_engine

# Import after setting up environment variables
from src.db.database import Base

async def setup_test_db():
    """Create test database tables."""
    # Use test database URL
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        raise ValueError("DATABASE_URL environment variable not set")
    
    print(f"Connecting to test database: {db_url}")
    engine = create_async_engine(db_url, echo=True)
    
    # Create all tables
    print("Creating test database tables...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    
    await engine.dispose()
    print("Test database setup complete!")

if __name__ == "__main__":
    # Load test environment variables
    from dotenv import load_dotenv
    
    # Load .env.test if it exists, otherwise use system environment
    load_dotenv(".env.test")
    
    asyncio.run(setup_test_db())
