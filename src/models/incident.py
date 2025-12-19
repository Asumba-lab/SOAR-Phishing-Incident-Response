from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Text, Enum, Boolean, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
import enum
from .base import Base, BaseModel

class IncidentStatus(str, enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"

class IncidentSeverity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class Incident(Base, BaseModel):
    """Security incident model."""
    __tablename__ = "incidents"
    
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(Enum(IncidentStatus), default=IncidentStatus.OPEN, nullable=False)
    severity = Column(Enum(IncidentSeverity), default=IncidentSeverity.MEDIUM, nullable=False)
    reported_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)
    source = Column(String(100), nullable=True)  # email, api, manual, etc.
    source_ref = Column(String(255), nullable=True)  # Reference to source (e.g., email ID)
    tags = Column(JSON, default=list, nullable=True)  # List of tags for categorization
    
    # Relationships
    reported_by_user = relationship("User", foreign_keys=[reported_by], back_populates="incidents")
    assigned_to_user = relationship("User", foreign_keys=[assigned_to])
    iocs = relationship("IOC", back_populates="incident", cascade="all, delete-orphan")
    analysis_results = relationship("AnalysisResult", back_populates="incident", cascade="all, delete-orphan")
    
    def to_dict(self, include_related: bool = False) -> dict:
        """Convert incident to dictionary."""
        data = {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "status": self.status.value,
            "severity": self.severity.value,
            "source": self.source,
            "source_ref": self.source_ref,
            "tags": self.tags or [],
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
        
        if include_related:
            data["reported_by"] = self.reported_by_user.to_dict() if self.reported_by_user else None
            data["assigned_to"] = self.assigned_to_user.to_dict() if self.assigned_to_user else None
            data["iocs"] = [ioc.to_dict() for ioc in self.iocs]
            data["analysis_results"] = [ar.to_dict() for ar in self.analysis_results]
            
        return data

class IOCTypes(str, enum.Enum):
    URL = "url"
    DOMAIN = "domain"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"
    CVE = "cve"
    FILENAME = "filename"
    REGISTRY = "registry"
    MUTEX = "mutex"
    USER_AGENT = "user_agent"
    BITCOIN = "bitcoin"
    OTHER = "other"

class IOC(Base, BaseModel):
    """Indicator of Compromise (IOC) model."""
    __tablename__ = "iocs"
    
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    type = Column(Enum(IOCTypes), nullable=False)
    value = Column(String(1000), nullable=False, index=True)
    description = Column(Text, nullable=True)
    is_malicious = Column(Boolean, default=False, nullable=False)
    confidence = Column(Integer, default=0)  # 0-100
    first_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    tags = Column(JSON, default=list, nullable=True)
    raw_data = Column(JSON, nullable=True)  # Raw data from source
    
    # Relationships
    incident = relationship("Incident", back_populates="iocs")
    analysis_results = relationship("AnalysisResult", back_populates="ioc")
    
    def to_dict(self, include_related: bool = False) -> dict:
        """Convert IOC to dictionary."""
        data = {
            "id": self.id,
            "type": self.type.value,
            "value": self.value,
            "description": self.description,
            "is_malicious": self.is_malicious,
            "confidence": self.confidence,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "tags": self.tags or [],
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
        
        if include_related and self.incident:
            data["incident"] = self.incident.to_dict()
            
        return data

class AnalysisResult(Base, BaseModel):
    """Analysis results for an incident or IOC."""
    __tablename__ = "analysis_results"
    
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    ioc_id = Column(Integer, ForeignKey("iocs.id", ondelete="CASCADE"), nullable=True)
    analyzed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    tool_name = Column(String(100), nullable=False)  # e.g., "virustotal", "otx", "custom"
    result = Column(JSON, nullable=False)  # Raw result from the analysis tool
    summary = Column(Text, nullable=True)  # Human-readable summary
    is_malicious = Column(Boolean, default=False, nullable=False)
    confidence = Column(Integer, default=0)  # 0-100
    
    # Relationships
    incident = relationship("Incident", back_populates="analysis_results")
    ioc = relationship("IOC", back_populates="analysis_results")
    analyzed_by_user = relationship("User", back_populates="analysis_results")
    
    def to_dict(self, include_related: bool = False) -> dict:
        """Convert analysis result to dictionary."""
        data = {
            "id": self.id,
            "tool_name": self.tool_name,
            "summary": self.summary,
            "is_malicious": self.is_malicious,
            "confidence": self.confidence,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
        
        if include_related:
            if self.incident:
                data["incident"] = self.incident.to_dict()
            if self.ioc:
                data["ioc"] = self.ioc.to_dict()
            if self.analyzed_by_user:
                data["analyzed_by"] = self.analyzed_by_user.to_dict()
                
        return data
