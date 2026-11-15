import asyncio
import sys
from secrets import compare_digest
from pathlib import Path
from typing import Annotated
from uuid import UUID

import uvicorn
import psycopg
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request, Security
from fastapi.security import APIKeyHeader
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from threat_monitor.telegram import send_alert
from threat_monitor.config import get_settings
from threat_monitor.contracts import (
    Alert,
    AlertDetail,
    AlertEvent,
    AlertStatus,
    AlertStatusChange,
    CollectionRunRequest,
    Company,
    CompanyCreate,
    CompanyPatch,
    Job,
    JobAccepted,
    Page,
    PostVersion,
    PostListPage,
    Severity,
    Source,
    SourceCreate,
)
from threat_monitor.storage.db import ConfigurationError, Conflict, NotFound
from threat_monitor.storage.repository import Store


app = FastAPI(
    title="scout.dev",
    version="0.1.0",
    description="Company threat intelligence, evidence-backed alerts, and background jobs.",
)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(request: Request, key: Annotated[str | None, Security(api_key_header)]):
    settings = get_settings()
    expected = settings.api_key
    if key and expected and compare_digest(key.encode(), expected.get_secret_value().encode()):
        return "member"
    if not key and request.headers.get("X-Guest-Access") == "1" and settings.guest_access_enabled:
        allowed = {"access_session", "list_companies", "get_company", "list_posts",
                   "get_post_version", "list_analysis_jobs", "list_alerts", "get_alert"}
        if request.method == "GET" and request.scope["route"].name in allowed:
            return "guest"
        raise HTTPException(status_code=403, detail="Guest access is read-only")
    if expected is None:
        raise HTTPException(status_code=503, detail="API_KEY is not configured")
    raise HTTPException(status_code=401, detail="Invalid or missing API key")


router = APIRouter(
    dependencies=[Depends(require_api_key)],
    responses={
        401: {"description": "Invalid or missing API key"},
        404: {"description": "Resource not found"},
        409: {"description": "Operation conflicts with current state"},
        503: {"description": "Required service configuration is missing"},
    },
)


def store():
    return Store(get_settings())


@app.exception_handler(NotFound)
async def not_found(request, exc):
    return JSONResponse(status_code=404, content={"detail": str(exc)})


@app.exception_handler(Conflict)
async def conflict(request, exc):
    return JSONResponse(status_code=409, content={"detail": str(exc)})


@app.exception_handler(ValueError)
async def invalid_input(request, exc):
    return JSONResponse(status_code=422, content={"detail": str(exc)})


@app.exception_handler(ConfigurationError)
async def configuration_error(request, exc):
    return JSONResponse(status_code=503, content={"detail": str(exc)})


@app.exception_handler(psycopg.Error)
async def database_error(request, exc):
    return JSONResponse(status_code=503, content={
        "detail": "Database unavailable or schema not initialized; run the database setup command",
    })


@app.get("/guest-access", tags=["access"])
async def guest_access():
    return {"enabled": get_settings().guest_access_enabled}


@router.get("/session", tags=["access"])
async def access_session(role: str = Depends(require_api_key)):
    return {"role": role}


@app.get("/health", tags=["health"])
async def health():
    return {"status": "ok"}


@app.get("/ready", tags=["health"])
async def ready():
    await store().ready()
    if not get_settings().api_key:
        raise ConfigurationError("API_KEY is not configured")
    return {"status": "ready", "scope": "api_database", "provider_connectivity": "not_checked"}


@router.post("/companies", response_model=Company, status_code=201, tags=["companies"])
async def create_company(company: CompanyCreate):
    return await store().create_company(company)


@router.get("/companies", response_model=Page[Company], tags=["companies"])
async def list_companies(
    cursor: str | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
):
    return await store().list_companies(cursor, limit)


@router.get("/companies/{company_id}", response_model=Company, tags=["companies"])
async def get_company(company_id: UUID):
    return await store().get_company(company_id)


@router.get("/posts", response_model=PostListPage, tags=["evidence"])
async def list_posts(
    cursor: str | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
):
    return await store().list_posts(cursor, limit)


@router.get("/post-versions/{version_id}", response_model=PostVersion, tags=["evidence"])
async def get_post_version(version_id: UUID):
    return await store().get_post(version_id)


@router.get("/companies/{company_id}/analysis-jobs", response_model=Page[Job], tags=["jobs"])
async def list_analysis_jobs(
    company_id: UUID,
    cursor: str | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
):
    return await store().list_analysis_jobs(company_id, cursor, limit)


@router.patch("/companies/{company_id}", response_model=Company, tags=["companies"])
async def update_company(company_id: UUID, change: CompanyPatch):
    return await store().update_company(company_id, change)


@router.post("/sources", response_model=Source, status_code=201, tags=["sources"])
async def create_source(source: SourceCreate):
    return await store().create_source(source)


@router.get("/sources", response_model=Page[Source], tags=["sources"])
async def list_sources(
    cursor: str | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
):
    return await store().list_sources(cursor, limit)


@router.post(
    "/collection-runs", response_model=JobAccepted, status_code=202, tags=["jobs"]
)
async def start_collection(request: CollectionRunRequest):
    ids = await store().enqueue_collection(request.source_ids)
    return JobAccepted(job_id=ids[0], job_ids=ids)


@router.post(
    "/companies/{company_id}/analysis-runs",
    response_model=JobAccepted,
    status_code=202,
    tags=["jobs"],
)
async def start_analysis(company_id: UUID):
    return JobAccepted(job_id=await store().enqueue_analysis(company_id))


@router.get("/jobs/{job_id}", response_model=Job, tags=["jobs"])
async def get_job(job_id: UUID):
    return await store().get_job(job_id)


@router.post("/jobs/{job_id}/retry", response_model=JobAccepted, status_code=202, tags=["jobs"])
async def retry_job(job_id: UUID):
    return JobAccepted(job_id=await store().retry_job(job_id))


@router.get(
    "/companies/{company_id}/alerts", response_model=Page[Alert], tags=["alerts"]
)
async def list_alerts(
    company_id: UUID,
    status: AlertStatus | None = None,
    severity: Severity | None = None,
    cursor: str | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
):
    return await store().list_alerts(company_id, status=status, severity=severity, cursor=cursor, limit=limit)


@router.post("/companies/{company_id}/telegram/latest-alert", tags=["alerts"])
async def send_latest_alert(company_id: UUID):
    repository = store()
    company = await repository.get_company(company_id)
    alerts = await repository.list_alerts(company_id, limit=1)
    if not alerts.items:
        raise NotFound("This company has no alerts to send")
    alert = alerts.items[0]
    message_id = await asyncio.to_thread(send_alert, get_settings(), company.name, alert)
    return {"alert_id": alert.id, "message_id": message_id}


@router.post("/alerts/{alert_id}/telegram", tags=["alerts"])
async def send_specific_alert(alert_id: UUID):
    repository = store()
    detail = await repository.get_alert(alert_id)
    company = await repository.get_company(detail.alert.company_id)
    message_id = await asyncio.to_thread(send_alert, get_settings(), company.name, detail.alert)
    return {"alert_id": detail.alert.id, "message_id": message_id}


@router.get("/alerts/{alert_id}", response_model=AlertDetail, tags=["alerts"])
async def get_alert(alert_id: UUID):
    return await store().get_alert(alert_id)


@router.patch("/alerts/{alert_id}/status", response_model=AlertEvent, tags=["alerts"])
async def change_alert_status(alert_id: UUID, change: AlertStatusChange):
    return await store().change_alert_status(alert_id, change)


app.include_router(router)

ui_dist = Path(__file__).resolve().parents[1] / "ui" / "dist"
app.mount("/app/assets", StaticFiles(directory=ui_dist / "assets", check_dir=False), name="ui-assets")


@app.get("/app", include_in_schema=False)
@app.get("/app/{path:path}", include_in_schema=False)
async def user_interface(path: str = ""):
    index = ui_dist / "index.html"
    if not index.is_file():
        raise HTTPException(status_code=503, detail="Build the interface with npm ci && npm run build in ui/")
    return FileResponse(index, headers={"Cache-Control": "no-cache"})


def main():
    settings = get_settings()
    uvicorn.run(
        "threat_monitor.api:app", host=settings.api_host, port=settings.api_port,
        loop="asyncio:SelectorEventLoop" if sys.platform == "win32" else "auto",
    )


if __name__ == "__main__":
    main()
