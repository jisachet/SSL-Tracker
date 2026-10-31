import sys
import argparse
from sqlalchemy.orm import Session
from app.database import SessionLocal, init_db
from app.models import Domain
from app.runner import check_all_domains_concurrently
from app.checker import check_ssl

def format_table(rows: list, headers: list) -> str:
    """Formats rows as a clean ASCII/Unicode table."""
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(val)))

    header_str = " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
    separator_str = "-+-".join("-" * col_widths[i] for i in range(len(headers)))
    
    lines = [header_str, separator_str]
    for row in rows:
        line = " | ".join(str(val).ljust(col_widths[i]) for i, val in enumerate(row))
        lines.append(line)
    return "\n".join(lines)

def run_cli():
    parser = argparse.ArgumentParser(description="BankSSL Tracker CLI")
    parser.add_argument("--all", action="store_true", help="Check and print status for all tracked domains")
    parser.add_argument("--domain", type=str, help="Check a specific domain on demand (e.g. example.com:443)")
    parser.add_argument("--no-refresh", action="store_true", help="Print existing database status without re-checking")
    
    args = parser.parse_args()

    init_db()

    if args.domain:
        parts = args.domain.split(":")
        host = parts[0]
        port = int(parts[1]) if len(parts) > 1 else 443
        print(f"Checking SSL for {host}:{port}...")
        res = check_ssl(host, port)
        print("\nResult:")
        for k, v in res.items():
            print(f"  {k:20}: {v}")
        return

    if args.all or not sys.argv[1:]:
        db: Session = SessionLocal()
        try:
            domains = db.query(Domain).all()
            if not domains:
                print("No domains found in database. Add domains via the web app or run with --domain <host>.")
                return

            if not args.no_refresh:
                print(f"Checking {len(domains)} domain(s) concurrently...")
                check_all_domains_concurrently()
                # Re-query updated domains
                db.expire_all()
                domains = db.query(Domain).all()

            # Sort by days remaining (soonest first)
            # None (unreachable/untested) should sort after known days remaining
            def sort_key(d: Domain):
                if d.days_remaining is None:
                    return 999999
                return d.days_remaining

            sorted_domains = sorted(domains, key=sort_key)

            headers = ["Domain:Port", "Label", "Status", "Days Left", "Expiry Date", "Issuer", "Last Checked"]
            rows = []
            for d in sorted_domains:
                target = f"{d.hostname}:{d.port}"
                label = d.label or "-"
                status = d.status or "NOT CHECKED"
                
                if d.days_remaining is not None:
                    if d.days_remaining < 0:
                        days_left = f"{d.days_remaining}d (EXPIRED)"
                    else:
                        days_left = f"{d.days_remaining}d"
                else:
                    days_left = "-"
                
                expiry = d.not_after.strftime("%Y-%m-%d") if d.not_after else "-"
                issuer = (d.issuer[:30] + "...") if d.issuer and len(d.issuer) > 30 else (d.issuer or "-")
                last_checked = d.last_checked_at.strftime("%Y-%m-%d %H:%M") if d.last_checked_at else "Never"

                rows.append([target, label, status, days_left, expiry, issuer, last_checked])

            print("\n" + format_table(rows, headers) + "\n")
            print(f"Total: {len(sorted_domains)} domain(s)")
        finally:
            db.close()
    else:
        parser.print_help()

if __name__ == "__main__":
    run_cli()
