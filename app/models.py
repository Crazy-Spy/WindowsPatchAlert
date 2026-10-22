"""Pydantic models for PATCH ALERT data validation and API serialization."""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field, HttpUrl


class HealthState(str, Enum):
    SAFE = "SAFE"
    MONITOR = "MONITOR"
    CAUTION = "CAUTION"
    AFFECTED = "AFFECTED"
    UNKNOWN = "UNKNOWN"


class UpdateType(str, Enum):
    CUMULATIVE = "Cumulative"
    SECURITY_ONLY = "Security Only"
    PREVIEW = "Preview"
    OOB = "Out-of-Band (OOB)"
    SERVICING_STACK = "Servicing Stack"


class IssueStatus(str, Enum):
    CONFIRMED = "Confirmed"
    INVESTIGATING = "Investigating"
    MITIGATED = "Mitigated"
    RESOLVED = "Resolved"


class KnownIssueModel(BaseModel):
    id: Optional[int] = None
    issue_key: str
    kb_number: str
    windows_version: str
    os_build: Optional[str] = None
    title: str
    symptoms: str
    status: str = Field(default="Confirmed")
    severity: str = Field(default="Moderate")  # Low, Moderate, High, Critical
    is_severe_failure: bool = False
    workaround: Optional[str] = None
    resolution: Optional[str] = None
    has_kir: bool = False
    kir_restart_required: Optional[bool] = None
    kir_deployment_method: Optional[str] = None
    kir_guidance_url: Optional[str] = None
    kir_gpo_name: Optional[str] = None
    oob_fix_kb: Optional[str] = None
    opened_date: Optional[str] = None
    last_updated_date: Optional[str] = None
    resolved_date: Optional[str] = None
    source_url: str
    content_hash: Optional[str] = None


class CVEModel(BaseModel):
    cve_id: str
    kb_number: Optional[str] = None
    title: str
    severity: str  # Critical, Important, Moderate, Low
    cvss_score: Optional[float] = None
    affected_component: str
    exploitability_status: str  # e.g., "Exploited:Yes", "Exploitation More Likely", "Exploitation Less Likely"
    is_exploited: bool = False
    publicly_disclosed: bool = False
    published_date: Optional[str] = None
    source_url: str


class KBRelationshipModel(BaseModel):
    id: Optional[int] = None
    kb_number: str
    related_kb: str
    relationship_type: str  # "supersedes", "superseded_by", "oob_replaces", "oob_replaced_by"
    issue_key: Optional[str] = None
    description: Optional[str] = None
    source_url: Optional[str] = None


class LifecycleEventModel(BaseModel):
    id: Optional[int] = None
    kb_number: str
    event_date: str
    event_type: str  # "Released", "Known Issue Reported", "KIR Issued", "OOB Issued", "Resolved", "Superseded"
    title: str
    details: str
    source_url: Optional[str] = None


class RiskEvaluationResult(BaseModel):
    status: HealthState
    rationale: str
    factors: list[str] = Field(default_factory=list)
    active_issues_count: int = 0
    mitigated_issues_count: int = 0
    resolved_issues_count: int = 0
    has_kir: bool = False
    has_oob_supersession: bool = False
    exploited_cve_count: int = 0


class KBSummaryModel(BaseModel):
    kb_number: str
    title: str
    windows_version: str
    os_build: str
    release_date: str
    patch_tuesday_cycle: str
    update_type: str
    is_security_update: bool
    is_oob: bool
    has_kir: bool
    health_status: HealthState
    health_rationale: str
    known_issues_count: int = 0
    active_issues_count: int = 0
    cve_count: int = 0
    exploited_cve_count: int = 0
    supersedes_kbs: list[str] = Field(default_factory=list)
    superseded_by_kbs: list[str] = Field(default_factory=list)
    oob_replaces_kbs: list[str] = Field(default_factory=list)
    oob_replaced_by_kbs: list[str] = Field(default_factory=list)
    source_url: str
    telemetry_verified: bool = True
    data_origin: str = "Microsoft Official"
    is_demo: bool = False
    last_checked_at: Optional[str] = None
    content_hash: Optional[str] = None


class KBDossierModel(KBSummaryModel):
    summary: Optional[str] = None
    highlights: Optional[str] = None
    known_issues: list[KnownIssueModel] = Field(default_factory=list)
    cves: list[CVEModel] = Field(default_factory=list)
    relationships: list[KBRelationshipModel] = Field(default_factory=list)
    lifecycle: list[LifecycleEventModel] = Field(default_factory=list)
    changes: list[ChangeLogModel] = Field(default_factory=list)
    risk_factors: list[str] = Field(default_factory=list)


class AlertModel(BaseModel):
    id: int
    kb_number: Optional[str] = None
    windows_version: Optional[str] = None
    severity: str  # AFFECTED, CAUTION, MONITOR, INFO
    alert_type: str  # OOB_RELEASE, KNOWN_ISSUE, KIR_ISSUED, EXPLOITED_CVE, STATUS_CHANGE, SOURCE_ERROR
    title: str
    summary: str
    source_url: Optional[str] = None
    acknowledged: bool = False
    acknowledged_at: Optional[str] = None
    is_demo: bool = False
    created_at: str


class ChangeLogModel(BaseModel):
    id: int
    entity_type: str  # KB, KNOWN_ISSUE, CVE, SOURCE
    entity_id: str
    kb_number: Optional[str] = None
    field_name: str
    old_value: Optional[str] = None
    new_value: Optional[str] = None
    change_type: str  # CREATED, UPDATED, STATUS_CHANGED
    content_hash: str
    source_url: Optional[str] = None
    is_demo: bool = False
    detected_at: str


class SourceConfigModel(BaseModel):
    id: int
    source_key: str
    name: str
    source_type: str
    windows_version: str
    url: str
    enabled: bool
    check_interval_minutes: int
    last_checked_at: Optional[str] = None
    last_success_at: Optional[str] = None
    last_status: str  # NEVER_CHECKED, OK, ERROR, DISABLED
    last_http_code: Optional[int] = None
    last_error: Optional[str] = None
    content_hash: Optional[str] = None
    items_collected: int = 0


class SourceUpdateInput(BaseModel):
    url: Optional[str] = Field(default=None, min_length=8, max_length=1000)
    enabled: Optional[bool] = None
    windows_version: Optional[str] = Field(default=None, min_length=2, max_length=120)
    check_interval_minutes: Optional[int] = Field(default=None, ge=5, le=10080)


KBDossierModel.model_rebuild()

