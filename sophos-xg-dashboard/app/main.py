from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.settings import load_settings
from app.sophos_api import (
    SophosClient,
    build_dashboard_summary,
    parse_firewall_rules,
    parse_nat_rules,
    sanitize_error,
)

app = FastAPI(title="Sophos XG/SFOS Dashboard", version="0.1.0")
app.mount("/static", StaticFiles(directory="/app/app/static"), name="static")
templates = Jinja2Templates(directory="/app/app/templates")


def client() -> SophosClient:
    settings = load_settings()
    return SophosClient(
        host=settings.sophos_host,
        username=settings.username,
        password=settings.password,
        verify_ssl=settings.verify_ssl,
        timeout=settings.request_timeout,
    )


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    settings = load_settings()
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "title": "Sophos XG/SFOS Dashboard",
            "sophos_host": settings.sophos_host,
            "refresh_interval": settings.refresh_interval,
        },
    )


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/firewall-rules")
async def firewall_rules() -> JSONResponse:
    try:
        raw = await client().get_firewall_rules_raw()
        return JSONResponse({"ok": True, **parse_firewall_rules(raw)})
    except Exception as exc:  # noqa: BLE001 - API errors must be returned as diagnostics
        return JSONResponse({"ok": False, "error": sanitize_error(exc)}, status_code=502)


@app.get("/api/nat-rules")
async def nat_rules() -> JSONResponse:
    try:
        raw = await client().get_nat_rules_raw()
        return JSONResponse({"ok": True, **parse_nat_rules(raw)})
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"ok": False, "error": sanitize_error(exc)}, status_code=502)


@app.get("/api/summary")
async def summary() -> JSONResponse:
    result: dict[str, object] = {"ok": True, "firewall_rules": None, "nat_rules": None, "dashboard": None, "errors": []}
    try:
        fw_raw = await client().get_firewall_rules_raw()
        result["firewall_rules"] = parse_firewall_rules(fw_raw)
    except Exception as exc:  # noqa: BLE001
        result["ok"] = False
        result["errors"].append({"source": "firewall_rules", "error": sanitize_error(exc)})

    try:
        nat_raw = await client().get_nat_rules_raw()
        result["nat_rules"] = parse_nat_rules(nat_raw)
    except Exception as exc:  # noqa: BLE001
        result["ok"] = False
        result["errors"].append({"source": "nat_rules", "error": sanitize_error(exc)})

    result["dashboard"] = build_dashboard_summary(
        result.get("firewall_rules") if isinstance(result.get("firewall_rules"), dict) else None,
        result.get("nat_rules") if isinstance(result.get("nat_rules"), dict) else None,
    )
    return JSONResponse(result, status_code=200 if result["ok"] else 502)
