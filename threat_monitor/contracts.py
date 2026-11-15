from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    AnyHttpUrl,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    model_validator,
)


EMBEDDING_DIMENSIONS = 768
Embedding = Annotated[
    list[float], Field(min_length=EMBEDDING_DIMENSIONS, max_length=EMBEDDING_DIMENSIONS)
]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class Page[T](Contract):
    items: list[T]
    next_cursor: str | None = None


class EmployeeRange(Contract):
    minimum: int | None = Field(default=None, ge=0)
    maximum: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def ordered_bounds(self):
        if self.minimum is not None and self.maximum is not None:
            if self.minimum > self.maximum:
                raise ValueError("minimum must not exceed maximum")
        return self


class RevenueRange(Contract):
    minimum: float | None = Field(default=None, ge=0)
    maximum: float | None = Field(default=None, ge=0)
    currency: str | None = None
    period: str | None = None

    @model_validator(mode="after")
    def ordered_bounds(self):
        if self.minimum is not None and self.maximum is not None:
            if self.minimum > self.maximum:
                raise ValueError("minimum must not exceed maximum")
        return self


class CompanyCreate(Contract):
    name: str = Field(min_length=1)
    aliases: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    industry: str | None = None
    countries: list[str] = Field(default_factory=list)
    employees: EmployeeRange | None = None
    revenue: RevenueRange | None = None
    technologies: list[str] = Field(default_factory=list)


class CompanyPatch(Contract):
    name: str | None = Field(default=None, min_length=1)
    aliases: list[str] | None = None
    domains: list[str] | None = None
    industry: str | None = None
    countries: list[str] | None = None
    employees: EmployeeRange | None = None
    revenue: RevenueRange | None = None
    technologies: list[str] | None = None

    @model_validator(mode="after")
    def reject_null_required_fields(self):
        for field in ("name", "aliases", "domains", "countries", "technologies"):
            if field in self.model_fields_set and getattr(self, field) is None:
                raise ValueError(f"{field} cannot be null")
        return self


class Company(CompanyCreate):
    next_analysis_at: AwareDatetime | None = None
    analysis_scheduling_error: str | None = None
    id: UUID
    profile_version: int = Field(ge=1)
    created_at: AwareDatetime
    updated_at: AwareDatetime


class SourceCreate(Contract):
    name: str = Field(min_length=1)
    url: AnyHttpUrl
    parser: str = Field(min_length=1)
    collection_settings: dict = Field(default_factory=dict)
    enabled: bool = True
    scan_interval_seconds: int = Field(default=86400, ge=60)
    revisit_days: int = Field(default=7, ge=0)


class Source(SourceCreate):
    id: UUID
    next_due_at: AwareDatetime | None = None
    last_attempt_at: AwareDatetime | None = None
    last_success_at: AwareDatetime | None = None


class ContextExtraction(Contract):
    markdown: str = Field(min_length=1)
    request_id: str | None = None


class NormalizedPost(Contract):
    source_id: UUID
    external_id: str | None = None
    thread_id: str | None = None
    url: AnyHttpUrl
    author: str | None = None
    published_at: AwareDatetime | None = None
    fetched_at: AwareDatetime
    title: str = ""
    text: str = Field(min_length=1)
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    context_extraction: ContextExtraction | None = None


class ThreatCategory(StrEnum):
    ACCESS_SALE = "access_sale"
    CREDENTIALS = "credentials"
    DATA_LEAK = "data_leak"
    EXPLOITATION = "exploitation"
    OTHER = "other"


class FactEvidence(Contract):
    field: str
    quote: str = Field(min_length=1)


class ExtractedFacts(Contract):
    company_names: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    industry: str | None = None
    countries: list[str] = Field(default_factory=list)
    employees: EmployeeRange | None = None
    revenue: RevenueRange | None = None
    technologies: list[str] = Field(default_factory=list)
    evidence: list[FactEvidence] = Field(default_factory=list)


class TargetClaim(Contract):
    label: str = Field(min_length=1)
    facts: ExtractedFacts = Field(default_factory=ExtractedFacts)


class PostTarget(TargetClaim):
    id: UUID
    ordinal: int = Field(ge=0)


class Classification(Contract):
    keep: bool
    reason: str = Field(min_length=1)
    category: ThreatCategory | None = None
    facts: ExtractedFacts = Field(default_factory=ExtractedFacts)
    targets: list[TargetClaim] = Field(default_factory=list)
    target_extraction_status: Literal["complete", "review_required"] = "review_required"

    @model_validator(mode="after")
    def project_target_facts(self):
        if "targets" in self.model_fields_set and (
            "target_extraction_status" not in self.model_fields_set
            or self.target_extraction_status == "complete"
        ):
            self.target_extraction_status = "complete"
            self.facts = self.targets[0].facts if len(self.targets) == 1 else ExtractedFacts()
        return self


class EmbeddedChunk(Contract):
    index: int = Field(ge=0)
    text: str = Field(min_length=1)
    start_char: int = Field(ge=0)
    end_char: int = Field(gt=0)
    embedding: Embedding
    embedding_model: str

    @model_validator(mode="after")
    def check_offsets(self):
        if self.end_char <= self.start_char:
            raise ValueError("end_char must exceed start_char")
        if self.end_char - self.start_char != len(self.text):
            raise ValueError("chunk length must match its character offsets")
        return self


class PostVersion(Contract):
    id: UUID
    post_id: UUID
    post: NormalizedPost
    classification: Classification
    targets: list[PostTarget] = Field(default_factory=list)


class PostSummary(Contract):
    version_id: UUID
    post_id: UUID
    source_id: UUID
    url: AnyHttpUrl
    title: str
    excerpt: str
    facts: ExtractedFacts
    fetched_at: AwareDatetime
    targets: list[PostTarget] = Field(default_factory=list)
    target_extraction_status: Literal["complete", "review_required"] = "review_required"


class PostListItem(Contract):
    version_id: UUID
    post_id: UUID
    source_name: str
    embedding_ready: bool
    title: str
    excerpt: str
    category: ThreatCategory
    published_at: AwareDatetime | None = None
    fetched_at: AwareDatetime


class PostListPage(Page[PostListItem]):
    total_count: int


class PostSearchPage(Page[PostSummary]):
    candidate_limit_reached: bool = False


class PostQuery(Contract):
    include_history: bool = False
    query: str | None = None
    source_ids: list[UUID] = Field(default_factory=list)
    categories: list[ThreatCategory] = Field(default_factory=list)
    countries: list[str] = Field(default_factory=list)
    industries: list[str] = Field(default_factory=list)
    employees: EmployeeRange | None = None
    technologies: list[str] = Field(default_factory=list)
    fetched_since: AwareDatetime | None = None
    cursor: str | None = None
    limit: int = Field(default=20, ge=1, le=100)


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(StrEnum):
    OPEN = "open"
    RESOLVED = "resolved"
    DISMISSED_NOT_TARGETED = "dismissed_not_targeted"


class Actor(StrEnum):
    USER = "user"
    MODEL = "model"


class AlertEvidence(Contract):
    post_version_id: UUID
    quote: str = Field(min_length=1)


class Finding(Contract):
    primary_post_version_id: UUID | None = None
    matched_target_ids: list[UUID] = Field(default_factory=list)
    title: str = Field(min_length=1)
    category: ThreatCategory
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    explanation: str = Field(min_length=1)
    matching_attributes: list[str] = Field(default_factory=list)
    conflicting_attributes: list[str] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)
    suggested_actions: list[str] = Field(default_factory=list)
    evidence: list[AlertEvidence] = Field(min_length=1)


class Alert(Finding):
    id: UUID
    company_id: UUID
    status: AlertStatus
    created_at: AwareDatetime
    updated_at: AwareDatetime


class AlertStatusChange(Contract):
    status: AlertStatus
    reason: str = Field(min_length=1)
    evidence: list[AlertEvidence] = Field(default_factory=list)


class AlertEvent(Contract):
    id: UUID
    alert_id: UUID
    previous_status: AlertStatus
    status: AlertStatus
    actor: Actor
    reason: str
    note: str
    evidence: list[AlertEvidence] = Field(default_factory=list)
    analysis_run_id: UUID | None = None
    created_at: AwareDatetime


class AlertDetail(Contract):
    alert: Alert
    events: list[AlertEvent]


class AnalysisContext(Contract):
    run_id: UUID
    company: Company
    post_versions: list[PostVersion]


class AnalysisResult(Contract):
    findings: list[Finding]
    processed_version_ids: list[UUID]
    incomplete_reason: str | None = None


class JobKind(StrEnum):
    COLLECTION = "collection"
    ANALYSIS = "analysis"


class JobState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    INCOMPLETE = "incomplete"


class CollectionRunRequest(Contract):
    source_ids: list[UUID] | None = Field(default=None, min_length=1)


class JobAccepted(Contract):
    job_id: UUID
    job_ids: list[UUID] = Field(default_factory=list)


class Job(Contract):
    id: UUID
    kind: JobKind
    state: JobState
    company_id: UUID | None = None
    source_ids: list[UUID] = Field(default_factory=list)
    collection_checkpoint: dict = Field(default_factory=dict)
    analysis_scope: Literal["full_corpus", "daily_candidates"] = "full_corpus"
    coverage: dict = Field(default_factory=dict)
    analysis_run_id: UUID | None = None
    processed_count: int = Field(default=0, ge=0)
    total_count: int | None = Field(default=None, ge=0)
    error: str | None = None
    created_at: AwareDatetime
    started_at: AwareDatetime | None = None
    finished_at: AwareDatetime | None = None
