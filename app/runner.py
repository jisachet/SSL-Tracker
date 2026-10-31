from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models import Domain, CheckHistory
from app.checker import check_ssl
from app.config import CHECK_TIMEOUT, MAX_WORKERS

def check_domain_by_id(domain_id: int, timeout: Optional[float] = None) -> Optional[Dict[str, Any]]:
    """
    Checks SSL for a domain by ID using its own DB session.
    Saves a CheckHistory record and updates the Domain cached fields.
    """
    effective_timeout = timeout if timeout is not None else CHECK_TIMEOUT
    db: Session = SessionLocal()
    try:
        domain = db.query(Domain).filter(Domain.id == domain_id).first()
        if not domain:
            return None

        hostname = domain.hostname
        port = domain.port

        # Run check
        res = check_ssl(hostname=hostname, port=port, timeout=effective_timeout)

        # Record in history
        history = CheckHistory(
            domain_id=domain.id,
            checked_at=res["checked_at"],
            status=res["status"],
            days_remaining=res["days_remaining"],
            not_after=res["not_after"],
            issuer=res["issuer"],
            subject_cn=res["subject_cn"],
            sans=res["sans"],
            chain_trusted=res["chain_trusted"],
            hostname_matches=res["hostname_matches"],
            tls_version=res["tls_version"],
            sha256_fingerprint=res["sha256_fingerprint"],
            error_message=res["error_message"],
        )
        db.add(history)

        # Update cached domain fields
        domain.last_checked_at = res["checked_at"]
        domain.status = res["status"]
        domain.days_remaining = res["days_remaining"]
        domain.not_after = res["not_after"]
        domain.issuer = res["issuer"]
        domain.subject_cn = res["subject_cn"]
        domain.sans = res["sans"]
        domain.chain_trusted = res["chain_trusted"]
        domain.hostname_matches = res["hostname_matches"]
        domain.tls_version = res["tls_version"]
        domain.sha256_fingerprint = res["sha256_fingerprint"]
        domain.error_message = res["error_message"]

        db.commit()
        return res
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()

def check_all_domains_concurrently(max_workers: Optional[int] = None, timeout: Optional[float] = None) -> Dict[str, Any]:
    """
    Checks all domains in the database concurrently using ThreadPoolExecutor.
    Each thread handles its own DB session.
    Returns summary stats.
    """
    workers = max_workers if max_workers is not None else MAX_WORKERS
    effective_timeout = timeout if timeout is not None else CHECK_TIMEOUT

    db: Session = SessionLocal()
    try:
        domain_ids = [d.id for d in db.query(Domain.id).all()]
    finally:
        db.close()

    total = len(domain_ids)
    if total == 0:
        return {"total": 0, "checked": 0, "errors": 0}

    checked_count = 0
    error_count = 0

    with ThreadPoolExecutor(max_workers=min(workers, total or 1)) as executor:
        future_to_id = {
            executor.submit(check_domain_by_id, d_id, effective_timeout): d_id
            for d_id in domain_ids
        }
        for future in as_completed(future_to_id):
            try:
                future.result()
                checked_count += 1
            except Exception:
                error_count += 1

    return {
        "total": total,
        "checked": checked_count,
        "errors": error_count,
    }
