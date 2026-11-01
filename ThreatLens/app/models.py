from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, UniqueConstraint, func
from app.database import Base

class IOC(Base):
    __tablename__ = "indicators"
    id = Column(Integer, primary_key=True, index=True)
    indicator = Column(String(500), unique=True, index=True, nullable=False)
    indicator_type = Column(String(20), nullable=False, index=True)
    severity = Column(String(20), default="medium", nullable=False, index=True)
    threat_score = Column(Integer, default=50, nullable=False, index=True)
    source = Column(String(100), default="manual", nullable=False)
    confidence = Column(Integer, default=50, nullable=False)
    tlp = Column(String(20), default="clear", nullable=False)
    status = Column(String(30), default="active", nullable=False, index=True)
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    tags = Column(Text, default="[]", nullable=False)
    attack_techniques = Column(Text, default="[]", nullable=False)
    analyst_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

class IOCSource(Base):
    __tablename__ = "indicator_sources"
    id = Column(Integer, primary_key=True, index=True)
    ioc_id = Column(Integer, ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False)
    source_name = Column(String(100), nullable=False)
    source_confidence = Column(Integer, default=50)
    first_reported = Column(DateTime, server_default=func.now())
    __table_args__ = (UniqueConstraint("ioc_id", "source_name", name="uq_indicator_source"),)

class FeedSyncRun(Base):
    __tablename__ = "feed_sync_runs"
    id = Column(Integer, primary_key=True, index=True)
    feed_name = Column(String(100), nullable=False)
    status = Column(String(20), default="success")
    fetched = Column(Integer, default=0)
    added = Column(Integer, default=0)
    duplicates = Column(Integer, default=0)
    invalid = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    started_at = Column(DateTime, server_default=func.now())
    completed_at = Column(DateTime, nullable=True)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    action = Column(String(50), nullable=False)
    entity_type = Column(String(50), nullable=False)
    entity_id = Column(String(100), nullable=True)
    details = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)


class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, index=True)
    ioc_id = Column(Integer, ForeignKey("indicators.id", ondelete="SET NULL"), nullable=True)
    title = Column(String(250), nullable=False)
    severity = Column(String(20), default="medium", nullable=False)
    status = Column(String(30), default="new", nullable=False, index=True)
    assignee = Column(String(120), nullable=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())


class Incident(Base):
    __tablename__ = "incidents"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(250), nullable=False)
    severity = Column(String(20), default="medium", nullable=False)
    status = Column(String(30), default="open", nullable=False, index=True)
    owner = Column(String(120), nullable=True)
    summary = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())


class SecurityEvent(Base):
    __tablename__ = "security_events"
    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String(80), nullable=False)
    indicator = Column(String(500), nullable=False, index=True)
    source = Column(String(100), default="internal")
    details = Column(Text, nullable=True)
    occurred_at = Column(DateTime, server_default=func.now(), nullable=False)


class IncidentTimeline(Base):
    __tablename__ = "incident_timeline"
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    event_type = Column(String(80), nullable=False)
    description = Column(Text, nullable=False)
    actor = Column(String(120), default="system")
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
