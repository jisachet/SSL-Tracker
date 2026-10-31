import io
import csv
from contextlib import asynccontextmanager
from typing import Optional
from fastapi import FastAPI, Depends, Request, Form, Query, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import or_, asc

from app.config import BASE_DIR, HOST, PORT
from app.database import init_db, get_db
from app.models import Domain, CheckHistory
from app.schemas import parse_and_validate_domain, parse_bulk_domains
from app.runner import check_domain_by_id, check_all_domains_concurrently

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables on app startup
    init_db()
    yield

app = FastAPI(title="BankSSL Tracker", lifespan=lifespan)

# Mount static files and templates
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "app" / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "app" / "templates"))

def get_color_code(status_str: Optional[str], days_remaining: Optional[int]) -> str:
    """
    Returns badge and row color classification:
    - green: > 30 days
    - yellow: 14 to 30
    - orange: 7 to 14
    - red: under 7 or expired
    - grey: unreachable or not checked
    - purple: invalid
    """
    if not status_str or status_str == "NOT CHECKED":
        return "grey"
    if status_str == "UNREACHABLE":
        return "grey"
    if status_str == "EXPIRED" or (days_remaining is not None and days_remaining < 0):
        return "red"
    if status_str == "INVALID":
        return "purple"
    if days_remaining is not None:
        if days_remaining < 7:
            return "red"
        elif days_remaining < 14:
            return "orange"
        elif days_remaining <= 30:
            return "yellow"
        else:
            return "green"
    return "grey"

# Custom template filters
templates.env.filters["abs"] = abs

@app.get("/", response_class=HTMLResponse)
def index_page(
    request: Request,
    q: Optional[str] = None,
    status: Optional[str] = None,
    msg: Optional[str] = None,
    type: Optional[str] = "info",
    db: Session = Depends(get_db),
):
    query = db.query(Domain)
    total_in_db = query.count()

    if q:
        search_term = f"%{q.strip()}%"
        query = query.filter(
            or_(
                Domain.hostname.ilike(search_term),
                Domain.label.ilike(search_term),
                Domain.issuer.ilike(search_term),
            )
        )

    if status:
        query = query.filter(Domain.status == status.strip())

    domains = query.all()

    # Sort domains: soonest days remaining first. None (unreachable/not checked) sorted at the end.
    def sort_key(d: Domain):
        if d.days_remaining is None:
            return (1, 999999)
        return (0, d.days_remaining)

    sorted_domains = sorted(domains, key=sort_key)

    decorated_domains = []
    for d in sorted_domains:
        code = get_color_code(d.status, d.days_remaining)
        decorated_domains.append({
            "domain": d,
            "color_code": code,
        })

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "domains": decorated_domains,
            "total_domains": total_in_db,
            "search_query": q or "",
            "selected_status": status or "",
            "flash_message": msg,
            "flash_type": type,
        },
    )

@app.get("/domains/new", response_class=HTMLResponse)
def new_domain_form(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="domain_form.html",
        context={
            "is_edit": False,
            "domain": None,
            "error": None,
        },
    )

@app.post("/domains/new", response_class=HTMLResponse)
def create_domain(
    request: Request,
    hostname: str = Form(...),
    port: int = Form(443),
    label: Optional[str] = Form(None),
    notes: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    try:
        clean_host, clean_port = parse_and_validate_domain(f"{hostname.strip()}:{port}")
    except ValueError as err:
        return templates.TemplateResponse(
            request=request,
            name="domain_form.html",
            context={
                "is_edit": False,
                "domain": None,
                "hostname_val": hostname,
                "port_val": port,
                "label_val": label,
                "notes_val": notes,
                "error": str(err),
            },
            status_code=400,
        )

    # Check uniqueness
    existing = db.query(Domain).filter(
        Domain.hostname == clean_host,
        Domain.port == clean_port,
    ).first()
    if existing:
        return templates.TemplateResponse(
            request=request,
            name="domain_form.html",
            context={
                "is_edit": False,
                "domain": None,
                "hostname_val": hostname,
                "port_val": port,
                "label_val": label,
                "notes_val": notes,
                "error": f"Domain {clean_host}:{clean_port} is already being tracked.",
            },
            status_code=400,
        )

    new_domain = Domain(
        hostname=clean_host,
        port=clean_port,
        label=label.strip() if label else None,
        notes=notes.strip() if notes else None,
    )
    db.add(new_domain)
    db.commit()
    db.refresh(new_domain)

    # Immediately perform initial SSL check
    try:
        check_domain_by_id(new_domain.id)
    except Exception:
        pass

    return RedirectResponse(
        url=f"/domains/{new_domain.id}?msg=Domain+added+and+checked+successfully&type=success",
        status_code=status.HTTP_303_SEE_OTHER,
    )

@app.get("/domains/bulk", response_class=HTMLResponse)
def bulk_add_form(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="bulk_add.html",
        context={
            "summary": None,
            "raw_input": "",
        },
    )

@app.post("/domains/bulk", response_class=HTMLResponse)
def process_bulk_add(
    request: Request,
    domain_list: str = Form(...),
    bulk_label: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    parsed = parse_bulk_domains(domain_list)
    valid_entries = parsed["valid"]
    duplicates_in_text = parsed["duplicates"]
    invalid_entries = parsed["invalid"]

    added = []
    skipped = []

    # Record internal list duplicates
    for dup in duplicates_in_text:
        skipped.append({
            "hostname": dup["hostname"],
            "port": dup["port"],
            "reason": "Duplicate within pasted list",
        })

    # Check each valid entry against database
    label_to_use = bulk_label.strip() if bulk_label else None
    new_domain_ids = []

    for item in valid_entries:
        host = item["hostname"]
        prt = item["port"]
        existing = db.query(Domain).filter(Domain.hostname == host, Domain.port == prt).first()
        if existing:
            skipped.append({
                "hostname": host,
                "port": prt,
                "reason": "Already exists in database",
            })
        else:
            domain_obj = Domain(
                hostname=host,
                port=prt,
                label=label_to_use,
            )
            db.add(domain_obj)
            db.commit()
            db.refresh(domain_obj)
            added.append({"hostname": host, "port": prt, "id": domain_obj.id})
            new_domain_ids.append(domain_obj.id)

    # Check newly added domains concurrently
    if new_domain_ids:
        for d_id in new_domain_ids:
            try:
                check_domain_by_id(d_id)
            except Exception:
                pass

    summary = {
        "added": added,
        "skipped": skipped,
        "rejected": invalid_entries,
    }

    return templates.TemplateResponse(
        request=request,
        name="bulk_add.html",
        context={
            "summary": summary,
            "raw_input": domain_list,
        },
    )

@app.get("/domains/{domain_id}", response_class=HTMLResponse)
def domain_detail(
    request: Request,
    domain_id: int,
    msg: Optional[str] = None,
    type: Optional[str] = "info",
    db: Session = Depends(get_db),
):
    domain = db.query(Domain).filter(Domain.id == domain_id).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")

    history = (
        db.query(CheckHistory)
        .filter(CheckHistory.domain_id == domain.id)
        .order_by(CheckHistory.checked_at.desc())
        .limit(100)
        .all()
    )

    color_code = get_color_code(domain.status, domain.days_remaining)

    return templates.TemplateResponse(
        request=request,
        name="domain_detail.html",
        context={
            "domain": domain,
            "history": history,
            "color_code": color_code,
            "flash_message": msg,
            "flash_type": type,
        },
    )

@app.get("/domains/{domain_id}/edit", response_class=HTMLResponse)
def edit_domain_form(
    request: Request,
    domain_id: int,
    db: Session = Depends(get_db),
):
    domain = db.query(Domain).filter(Domain.id == domain_id).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")

    return templates.TemplateResponse(
        request=request,
        name="domain_form.html",
        context={
            "is_edit": True,
            "domain": domain,
            "error": None,
        },
    )

@app.post("/domains/{domain_id}/edit", response_class=HTMLResponse)
def update_domain(
    request: Request,
    domain_id: int,
    hostname: str = Form(...),
    port: int = Form(443),
    label: Optional[str] = Form(None),
    notes: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    domain = db.query(Domain).filter(Domain.id == domain_id).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")

    try:
        clean_host, clean_port = parse_and_validate_domain(f"{hostname.strip()}:{port}")
    except ValueError as err:
        return templates.TemplateResponse(
            request=request,
            name="domain_form.html",
            context={
                "is_edit": True,
                "domain": domain,
                "error": str(err),
            },
            status_code=400,
        )

    # Check uniqueness excluding self
    conflict = (
        db.query(Domain)
        .filter(
            Domain.hostname == clean_host,
            Domain.port == clean_port,
            Domain.id != domain.id,
        )
        .first()
    )
    if conflict:
        return templates.TemplateResponse(
            request=request,
            name="domain_form.html",
            context={
                "is_edit": True,
                "domain": domain,
                "error": f"Another domain with {clean_host}:{clean_port} already exists.",
            },
            status_code=400,
        )

    domain.hostname = clean_host
    domain.port = clean_port
    domain.label = label.strip() if label else None
    domain.notes = notes.strip() if notes else None
    db.commit()

    return RedirectResponse(
        url=f"/domains/{domain.id}?msg=Domain+updated+successfully&type=success",
        status_code=status.HTTP_303_SEE_OTHER,
    )

@app.post("/domains/{domain_id}/delete")
def delete_domain(
    domain_id: int,
    db: Session = Depends(get_db),
):
    domain = db.query(Domain).filter(Domain.id == domain_id).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")

    target = f"{domain.hostname}:{domain.port}"
    db.delete(domain)
    db.commit()

    return RedirectResponse(
        url=f"/?msg=Deleted+domain+{target}&type=info",
        status_code=status.HTTP_303_SEE_OTHER,
    )

@app.post("/domains/{domain_id}/check")
def check_single_domain_route(
    domain_id: int,
    request: Request,
):
    res = check_domain_by_id(domain_id)
    if not res:
        raise HTTPException(status_code=404, detail="Domain not found")

    referer = request.headers.get("referer") or f"/domains/{domain_id}"
    sep = "&" if "?" in referer else "?"
    status_msg = f"Check completed: {res['status']}"
    return RedirectResponse(
        url=f"{referer}{sep}msg={status_msg}&type=success",
        status_code=status.HTTP_303_SEE_OTHER,
    )

@app.post("/domains/check-all")
def check_all_domains_route():
    summary = check_all_domains_concurrently()
    msg = f"Checked {summary['checked']} domains concurrently ({summary['errors']} errors)"
    return RedirectResponse(
        url=f"/?msg={msg}&type=success",
        status_code=status.HTTP_303_SEE_OTHER,
    )

@app.get("/export/csv")
def export_csv(db: Session = Depends(get_db)):
    domains = db.query(Domain).all()

    def sort_key(d: Domain):
        if d.days_remaining is None:
            return 999999
        return d.days_remaining

    sorted_domains = sorted(domains, key=sort_key)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Hostname",
        "Port",
        "Label",
        "Status",
        "Days Remaining",
        "Expiry Date (UTC)",
        "Issuer",
        "Subject CN",
        "SANs",
        "Chain Trusted",
        "Hostname Matches",
        "TLS Version",
        "SHA-256 Fingerprint",
        "Last Checked (UTC)",
        "Notes",
    ])

    for d in sorted_domains:
        writer.writerow([
            d.hostname,
            d.port,
            d.label or "",
            d.status or "NOT CHECKED",
            d.days_remaining if d.days_remaining is not None else "",
            d.not_after.strftime("%Y-%m-%d %H:%M:%S") if d.not_after else "",
            d.issuer or "",
            d.subject_cn or "",
            d.sans or "",
            "Yes" if d.chain_trusted else ("No" if d.chain_trusted is not None else ""),
            "Yes" if d.hostname_matches else ("No" if d.hostname_matches is not None else ""),
            d.tls_version or "",
            d.sha256_fingerprint or "",
            d.last_checked_at.strftime("%Y-%m-%d %H:%M:%S") if d.last_checked_at else "",
            d.notes or "",
        ])

    csv_data = output.getvalue()
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=bankssl_domains.csv"},
    )

@app.post("/seed")
def seed_sample_domains(db: Session = Depends(get_db)):
    samples = [
        {"hostname": "google.com", "port": 443, "label": "Google Search Gateway", "notes": "Production Public Search"},
        {"hostname": "github.com", "port": 443, "label": "GitHub Code Registry", "notes": "Git VCS Endpoint"},
        {"hostname": "badssl.com", "port": 443, "label": "BadSSL Reference", "notes": "SSL Reference Testbed"},
    ]

    added_ids = []
    for s in samples:
        exists = db.query(Domain).filter(Domain.hostname == s["hostname"], Domain.port == s["port"]).first()
        if not exists:
            d = Domain(
                hostname=s["hostname"],
                port=s["port"],
                label=s["label"],
                notes=s["notes"],
            )
            db.add(d)
            db.commit()
            db.refresh(d)
            added_ids.append(d.id)

    # Run check on newly added sample domains
    for d_id in added_ids:
        try:
            check_domain_by_id(d_id)
        except Exception:
            pass

    return RedirectResponse(
        url="/?msg=Sample+domains+seeded+and+checked+successfully&type=success",
        status_code=status.HTTP_303_SEE_OTHER,
    )

@app.get("/health")
def health_check():
    return {"status": "ok", "app": "BankSSL Tracker"}
