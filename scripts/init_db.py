import os
import sys
from pathlib import Path

# Add the project root to the Python path
project_root = str(Path(__file__).parent.parent)
sys.path.insert(0, project_root)

import logging
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

from src.config import settings
from src.db.database import Base, engine
from src.models.user import User, APIToken
from src.models.incident import Incident, IOC, AnalysisResult
from src.models.threat_intel import ThreatIntelCache

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def init_database():
    """Initialize the database by creating all tables."""
    try:
        # Create all tables
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
        
        # Test the connection
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            
        logger.info("Database connection test successful")
        
    except SQLAlchemyError as e:
        logger.error(f"Error initializing database: {e}")
        sys.exit(1)

def create_initial_admin():
    """Create an initial admin user if no users exist."""
    from sqlalchemy.orm import sessionmaker
    from src.core.security import get_password_hash
    
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    
    try:
        # Check if any users exist
        if db.query(User).first() is None:
            # Create admin user
            admin = User(
                email="admin@example.com",
                hashed_password=get_password_hash("admin123"),
                full_name="Admin User",
                is_active=True,
                role="admin"
            )
            db.add(admin)
            db.commit()
            logger.info("Created initial admin user: admin@example.com / admin123")
    except Exception as e:
        logger.error(f"Error creating initial admin user: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    logger.info("Initializing database...")
    init_database()
    create_initial_admin()
    logger.info("Database initialization complete")
