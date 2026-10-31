from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    DateTime,
    Boolean,
    ForeignKey,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship
from app.database import Base

def utc_now():
    return datetime.now(timezone.utc)

class Domain(Base):
    __tablename__ = "domains"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(255), nullable=False, index=True)
    port = Column(Integer, default=443, nullable=False)
    label = Column(String(255), nullable=True)
    notes = Column(Text, nullable=True)
    
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    # Cached latest check results for fast table sorting and filtering
    last_checked_at = Column(DateTime(timezone=True), nullable=True)
    status = Column(String(50), default="NOT CHECKED", nullable=False, index=True)
    days_remaining = Column(Integer, nullable=True, index=True)
    not_after = Column(DateTime(timezone=True), nullable=True)
    issuer = Column(String(255), nullable=True)
    subject_cn = Column(String(255), nullable=True)
    sans = Column(Text, nullable=True)
    chain_trusted = Column(Boolean, nullable=True)
    hostname_matches = Column(Boolean, nullable=True)
    tls_version = Column(String(50), nullable=True)
    sha256_fingerprint = Column(String(100), nullable=True)
    error_message = Column(Text, nullable=True)

    history = relationship(
        "CheckHistory",
        back_populates="domain",
        cascade="all, delete-orphan",
        order_by="desc(CheckHistory.checked_at)",
    )

    __table_args__ = (
        UniqueConstraint("hostname", "port", name="uq_domain_hostname_port"),
    )

    @property
    def target(self) -> str:
        return f"{self.hostname}:{self.port}"


class CheckHistory(Base):
    __tablename__ = "check_history"

    id = Column(Integer, primary_key=True, index=True)
    domain_id = Column(Integer, ForeignKey("domains.id", ondelete="CASCADE"), nullable=False, index=True)
    checked_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    status = Column(String(50), nullable=False)
    days_remaining = Column(Integer, nullable=True)
    not_after = Column(DateTime(timezone=True), nullable=True)
    issuer = Column(String(255), nullable=True)
    subject_cn = Column(String(255), nullable=True)
    sans = Column(Text, nullable=True)
    chain_trusted = Column(Boolean, nullable=True)
    hostname_matches = Column(Boolean, nullable=True)
    tls_version = Column(String(50), nullable=True)
    sha256_fingerprint = Column(String(100), nullable=True)
    error_message = Column(Text, nullable=True)

    domain = relationship("Domain", back_populates="history")
