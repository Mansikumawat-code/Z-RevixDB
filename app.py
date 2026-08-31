"""Z-RevixDB Application Entrypoint.

Enterprise Data Versioning, Time-Travel & Recovery Platform.
Zero Third-Party Runtime Dependencies.
"""

import sys
from zrevixdb.audit import register_audit_routes
from zrevixdb.auth import register_auth_routes, seed_admin_user
from zrevixdb.dashboard import register_dashboard_routes
from zrevixdb.diff import register_diff_routes
from zrevixdb.integrity import register_integrity_routes
from zrevixdb.recovery import print_startup_recovery_report, run_crash_recovery_scan
from zrevixdb.search import register_search_routes
from zrevixdb.server import Response, Router, run_server
from zrevixdb.storage import DEFAULT_DB_PATH
from zrevixdb.versioning import register_record_routes

BANNER = r"""
======================================================================
  ______     _____            _      _____  ____  
 |___  /    |  __ \          (_)    |  __ \|  _ \ 
    / /____ | |__) |_____   ___  ___| |  | | |_) |
   / /______|  _  // _ \ \ / / |/ __| |  | |  _ < 
  / /__     | | \ \  __/\ V /| | (__| |__| | |_) |
 /_____|    |_|  \_\___| \_/ |_|\___|_____/|____/ 
                                                  
  Enterprise Data Versioning & Time-Travel Platform
  [Zero Third-Party Dependencies • Python 3 Stdlib]
======================================================================
"""


def main():
    host = "127.0.0.1"
    port = 8000

    print(BANNER)
    print(f"[*] Booting Z-RevixDB Engine...")

    # Execute Pre-flight Crash Recovery Scan
    recovery_summary = run_crash_recovery_scan(db_path=DEFAULT_DB_PATH)
    print_startup_recovery_report(recovery_summary)

    # Seed Admin User
    admin_user, admin_pass, created = seed_admin_user(db_path=DEFAULT_DB_PATH)
    if created:
        print("\n" + "=" * 54)
        print(" [!] INITIAL ADMIN ACCOUNT CREATED")
        print(f"     Username : {admin_user}")
        print(f"     Password : {admin_pass}")
        print("     Role     : Admin")
        print(" [!] Please store these credentials safely.")
        print("=" * 54 + "\n")
    else:
        print(f"[✓] Admin user account '{admin_user}' verified.")

    router = Router()

    # Health check endpoint
    @router.get("/api/health")
    def health_check(req):
        return Response.json({
            "status": "healthy",
            "service": "Z-RevixDB",
            "version": "0.1.0",
            "recovery_state": recovery_summary["status"],
            "dependencies": "0 (stdlib-only)"
        })

    # Register all Engine & API routes
    register_auth_routes(router, db_path=DEFAULT_DB_PATH)
    register_record_routes(router, db_path=DEFAULT_DB_PATH)
    register_diff_routes(router, db_path=DEFAULT_DB_PATH)
    register_integrity_routes(router, db_path=DEFAULT_DB_PATH)
    register_audit_routes(router, db_path=DEFAULT_DB_PATH)
    register_search_routes(router, db_path=DEFAULT_DB_PATH)
    register_dashboard_routes(router, db_path=DEFAULT_DB_PATH)

    print(f"\n[*] Starting HTTP server on http://{host}:{port} ...")
    print(f"[*] Control Center    : http://{host}:{port}/dashboard.html")
    print(f"[*] Records & Lineage : http://{host}:{port}/records.html")
    print(f"[*] Version Diffing   : http://{host}:{port}/compare.html")
    print(f"[*] Integrity Monitor : http://{host}:{port}/integrity.html")
    print(f"[*] Enterprise Audit  : http://{host}:{port}/audit.html")
    print(f"[*] Full-Text Search  : http://{host}:{port}/search.html")
    print(f"[*] Version Timeline  : http://{host}:{port}/timeline.html")
    print(f"[*] User Settings     : http://{host}:{port}/settings.html")
    print("----------------------------------------------------------------------")
    print("Press Ctrl+C to stop the server.\n")

    server = run_server(host=host, port=port, router=router)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down Z-RevixDB gracefully...")
    finally:
        server.server_close()
        print("[✓] Server stopped.")


if __name__ == "__main__":
    main()
