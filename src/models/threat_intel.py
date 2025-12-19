from sqlalchemy import Column, String, Integer, DateTime, Text, JSON, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime, timedelta
from .base import Base, BaseModel

class ThreatIntelCache(Base, BaseModel):
    """Cache for threat intelligence lookups."""
    __tablename__ = "threat_intel_cache"
    
    indicator_type = Column(String(50), nullable=False, index=True)
    indicator = Column(String(1000), nullable=False, index=True)
    source = Column(String(100), nullable=False)  # e.g., "virustotal", "otx"
    data = Column(JSON, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    is_malicious = Column(Boolean, default=False, nullable=False)
    confidence = Column(Integer, default=0)  # 0-100
    
    # Index for faster lookups
    __table_args__ = (
        {"mysql_charset": "utf8mb4", "mysql_collate": "utf8mb4_unicode_ci"},
    )
    
    @classmethod
    def get_cache_key(cls, indicator_type: str, indicator: str, source: str) -> str:
        """Generate a cache key."""
        return f"{source}:{indicator_type}:{indicator.lower()}"
    
    @classmethod
    def is_expired(cls, expires_at: datetime) -> bool:
        """Check if cache entry is expired."""
        return datetime.utcnow() > expires_at
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "indicator_type": self.indicator_type,
            "indicator": self.indicator,
            "source": self.source,
            "is_malicious": self.is_malicious,
            "confidence": self.confidence,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
