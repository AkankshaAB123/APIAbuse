from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from fastapi.responses import HTMLResponse, JSONResponse

from backend.lab.bola_lab import (
    get_lab_resource,
    run_bola_attack_lab,
    vulnerable_resource_request,
)
from backend.lab.dos_flood_lab import (
    flood_target_request,
    run_dos_flood_attack_lab,
)
from backend.lab.phishing_lab import (
    handle_victim_phishing_get,
    phishing_blocked_page_html,
    phishing_login_page_html,
    phishing_page_blocked,
    process_dummy_phishing_submission,
    run_phishing_attack_lab,
    run_synthetic_phishing_email_lab,
)
from backend.lab.sql_injection_lab import (
    run_sql_injection_attack_lab,
    vulnerable_product_search,
)
from backend.lab.ssrf_lab import (
    restricted_internal_resource,
    run_ssrf_attack_lab,
    vulnerable_ssrf_fetch,
)


router = APIRouter(prefix="/lab", tags=["Controlled Security Lab"])


class PhishingLoginRequest(BaseModel):
    username: str
    password: str


class SyntheticPhishingEmailRequest(BaseModel):
    target_enterprise: str
    sender: str
    recipient: str
    subject: str
    email_body: str
    suspicious_url: str


@router.get("/resources/{resource_id}")
def read_lab_resource(resource_id: str, requester: str = "user_101"):
    target_result = vulnerable_resource_request(
        requester_user_id=requester,
        requested_resource_id=resource_id,
    )

    if target_result["status_code"] == 404:
        raise HTTPException(
            status_code=404,
            detail="Lab resource not found",
        )

    return {
        "requester": requester,
        "resource": get_lab_resource(resource_id),
        "vulnerable_target_response": target_result,
    }


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@router.post("/attacks/bola")
def launch_bola_attack(request: Request):
    return run_bola_attack_lab(source_ip=_client_ip(request))


@router.get("/products/search")
def search_lab_products(query: str = "Laptop"):
    return {
        "query": query,
        "vulnerable_target_response": vulnerable_product_search(query),
    }


@router.post("/attacks/sql-injection")
def launch_sql_injection_attack(request: Request):
    return run_sql_injection_attack_lab(source_ip=_client_ip(request))


@router.get("/internal/restricted")
def read_restricted_internal_resource():
    return restricted_internal_resource()


@router.post("/fetch")
def fetch_url(url: str):
    return {
        "url": url,
        "vulnerable_target_response": vulnerable_ssrf_fetch(url),
    }


@router.post("/attacks/ssrf")
def launch_ssrf_attack(request: Request):
    return run_ssrf_attack_lab(source_ip=_client_ip(request))


@router.get("/flood-target")
def read_flood_target(source: str = "127.0.0.1"):
    result = flood_target_request(source)
    return JSONResponse(
        status_code=result["status_code"],
        content=result,
    )


@router.post("/attacks/dos-flood")
def launch_dos_flood_attack(request: Request):
    return run_dos_flood_attack_lab(client_ip=_client_ip(request))


ALLOWED_PHISHING_SCENARIOS = {"login", "verify", "reward", "account"}


@router.get("/phishing/{scenario}")
def read_phishing_scenario_page(scenario: str, request: Request):
    if scenario not in ALLOWED_PHISHING_SCENARIOS:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario}' not found.")

    if phishing_page_blocked(scenario):
        return HTMLResponse(
            content=phishing_blocked_page_html(),
            status_code=403,
        )

    source_ip = _client_ip(request)
    host_header = request.headers.get("host", "10.165.192.186")
    raw_host = host_header.split(":")[0] if host_header else "10.165.192.186"
    destination_ip = "10.165.192.186" if raw_host in ("testserver", "10.165.192.186", "localhost", "127.0.0.1") else raw_host
    user_agent = request.headers.get("user-agent", "Victim-Browser")

    is_blocked, content, status_code = handle_victim_phishing_get(
        scenario=scenario,
        source_ip=source_ip,
        destination_ip=destination_ip,
        user_agent=user_agent,
    )
    return HTMLResponse(
        content=content,
        status_code=status_code,
    )


@router.post("/phishing/{scenario}")
def submit_phishing_scenario(scenario: str, payload: PhishingLoginRequest):
    if scenario not in ALLOWED_PHISHING_SCENARIOS:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario}' not found.")

    if phishing_page_blocked(scenario):
        return JSONResponse(
            status_code=403,
            content={
                "status_code": 403,
                "body": {
                    "error": "page_blocked",
                    "reason": f"Controlled phishing {scenario} lab page is blocked.",
                },
                "credential_capture_observed": False,
            },
        )

    result = process_dummy_phishing_submission(
        username=payload.username,
        password=payload.password,
    )

    return JSONResponse(
        status_code=result["status_code"],
        content=result,
    )


@router.post("/attacks/phishing")
def launch_phishing_attack(request: Request):
    return run_phishing_attack_lab(source_ip=_client_ip(request))


@router.post("/attacks/phishing-email")
def launch_synthetic_phishing_email(
    payload: SyntheticPhishingEmailRequest,
    request: Request,
):
    return run_synthetic_phishing_email_lab(
        email=payload.model_dump(),
        source_ip=_client_ip(request),
    )
