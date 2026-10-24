"""Data models for Microsoft Defender XDR Alerts, Incidents, and AI SOC Analysis."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AlertSeverity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    UNKNOWN = "unknown"


class AlertStatus(str, Enum):
    NEW = "new"
    IN_PROGRESS = "inProgress"
    RESOLVED = "resolved"
    UNKNOWN = "unknown"


class TriageVerdict(str, Enum):
    TRUE_POSITIVE = "True Positive (Malicious)"
    FALSE_POSITIVE = "False Positive (Benign/Authorized)"
    SUSPICIOUS = "Suspicious (Needs Further Investigation)"
    BENIGN_POSITIVE = "Benign Positive (Expected Security Test/Admin Tool)"


class EntityType(str, Enum):
    DEVICE = "device"
    USER = "user"
    FILE = "file"
    PROCESS = "process"
    IP = "ip"
    URL = "url"
    MAILBOX = "mailbox"
    APPLICATION = "application"
    CLOUD_RESOURCE = "cloudResource"


class AlertEntity(BaseModel):
    entity_type: EntityType
    identifier: str
    details: Dict[str, Any] = Field(default_factory=dict)
    reputation: Optional[str] = None


class MitreTechnique(BaseModel):
    technique_id: str
    name: str
    tactic: str
    description: Optional[str] = None


class DefenderAlert(BaseModel):
    id: str
    title: str
    description: Optional[str] = ""
    severity: AlertSeverity = AlertSeverity.LOW
    status: AlertStatus = AlertStatus.NEW
    category: Optional[str] = "Unknown"
    created_date_time: Optional[datetime] = None
    last_update_date_time: Optional[datetime] = None
    incident_id: Optional[str] = None
    service_source: Optional[str] = "microsoftDefenderForEndpoint"
    detection_source: Optional[str] = None
    provider_alert_id: Optional[str] = None
    recommended_actions: Optional[str] = None
    mitre_techniques: List[MitreTechnique] = Field(default_factory=list)
    entities: List[AlertEntity] = Field(default_factory=list)
    raw_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    raw_payload: Optional[Dict[str, Any]] = Field(default_factory=dict)


class ContainmentAction(BaseModel):
    action: str
    target_entity: str
    priority: str = "High"  # Immediate, High, Medium, Low
    rationale: str
    automated_capability: bool = True  # Can this be automated via Defender API?


class KqlHuntingQuery(BaseModel):
    title: str
    description: str
    table: str  # e.g., DeviceProcessEvents, DeviceNetworkEvents, SigninLogs
    query: str


class AIAnalysisReport(BaseModel):
    alert_id: str
    alert_title: str
    verdict: TriageVerdict
    confidence_score: int = Field(ge=0, le=100)  # 0 to 100%
    severity_assessment: AlertSeverity
    executive_summary: str
    technical_narrative: str
    attack_vector: str
    mitre_attack_chain: List[MitreTechnique] = Field(default_factory=list)
    impacted_entities: List[AlertEntity] = Field(default_factory=list)
    blast_radius_assessment: str
    false_positive_indicators: List[str] = Field(default_factory=list)
    containment_actions: List[ContainmentAction] = Field(default_factory=list)
    hunting_queries: List[KqlHuntingQuery] = Field(default_factory=list)
    next_steps_for_analyst: List[str] = Field(default_factory=list)
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    model_used: str = "AI SOC Analyst"
