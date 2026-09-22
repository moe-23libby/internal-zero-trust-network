#!/usr/bin/env python3
"""
ZTNA Protected Company Server / Policy Enforcement Point (PEP)

Architecture mapping:
- Policy Engine (PE): policy_engine.evaluate_session_access()
- Policy Administrator (PA): policy_administrator.revoke_session()
- PE + PA = Policy Decision Point (PDP)
- This application = Policy Enforcement Point (PEP)

Every protected resource request is re-evaluated by the Policy Engine.
The PEP does not assume that a successful initial login remains valid forever.
"""

import os
import sys
from functools import wraps

from flask import (
    Flask,
    g,
    make_response,
    redirect,
    render_template_string,
    request,
)


# ============================================================
# PROJECT PATH
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


# Import project modules only after BASE_DIR is available.
from database import get_connection
from policy_engine import evaluate_session_access
from policy_administrator import revoke_session

try:
    from security_utils import log_access
except ImportError:
    # Keeps the PEP usable even if access-history logging is unavailable.
    log_access = None


# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(__name__)

SERVER_IP = "192.168.30.10"
SERVER_PORT = 8000
MFA_LOGIN_URL = "https://192.168.30.10:5050/login"
SESSION_COOKIE_NAME = "ztna_session"


# ============================================================
# DATABASE HELPERS
# ============================================================

def close_database(cursor=None, db=None):
    try:
        if cursor is not None:
            cursor.close()
    except Exception:
        pass

    try:
        if db is not None:
            db.close()
    except Exception:
        pass


def get_session_record(session_id):
    """Return the server-side session, even if it is no longer ACTIVE."""

    if not session_id:
        return None

    db = None
    cursor = None

    try:
        db = get_connection()
        cursor = db.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT
                id,
                session_id,
                username,
                device_ip,
                status,
                created_at,
                last_seen,
                revoked_at,
                mfa_verified,
                certificate_verified,
                auth_level
            FROM access_sessions
            WHERE session_id = %s
            LIMIT 1
            """,
            (session_id,),
        )

        return cursor.fetchone()

    except Exception as error:
        print("[SESSION LOOKUP ERROR]", error)
        return None

    finally:
        close_database(cursor, db)


def touch_session(session_id):
    """Update last_seen only after the PDP grants the current request."""

    if not session_id:
        return

    db = None
    cursor = None

    try:
        db = get_connection()
        cursor = db.cursor()

        cursor.execute(
            """
            UPDATE access_sessions
            SET last_seen = NOW()
            WHERE session_id = %s
              AND status = 'ACTIVE'
            """,
            (session_id,),
        )

        db.commit()

    except Exception as error:
        print("[SESSION TOUCH ERROR]", error)

    finally:
        close_database(cursor, db)


def get_policy_permission(role, resource):
    """
    Read the human-readable permission for display purposes.

    The actual access decision is NOT made here. The Policy Engine is the
    authority for GRANT / DENY / REVOKE decisions.
    """

    if not role or not resource:
        return "Not permitted"

    db = None
    cursor = None

    try:
        db = get_connection()
        cursor = db.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT permission
            FROM enterprise_policies
            WHERE role = %s
              AND resource = %s
              AND enabled = 1
            ORDER BY id DESC
            LIMIT 1
            """,
            (role.lower(), resource.lower()),
        )

        row = cursor.fetchone()

        if not row:
            return "Not permitted"

        permission = (row.get("permission") or "").upper()

        # The policy table currently stores ALLOW/DENY.  Give the portal a
        # simple readable description without changing the decision itself.
        if permission == "ALLOW":
            return "Allowed by enterprise policy"
        if permission == "DENY":
            return "Denied by enterprise policy"

        return permission or "Not permitted"

    except Exception as error:
        print("[POLICY PERMISSION ERROR]", error)
        return "Policy controlled"

    finally:
        close_database(cursor, db)


def safe_log_access(username, role, device_ip, resource, result, reason):
    """Write access history without allowing a logging failure to break PEP."""

    if log_access is None:
        return

    try:
        log_access(
            username=username,
            role=role,
            device_ip=device_ip,
            resource=resource,
            action="ACCESS",
            result=result,
            reason=reason,
        )
    except Exception as error:
        print("[ACCESS HISTORY ERROR]", error)


# ============================================================
# PEP HELPERS
# ============================================================

def current_client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "").strip()

    if forwarded:
        return forwarded.split(",")[0].strip()

    return request.remote_addr or "unknown"


def build_request_state(result, session):
    """Create one view model for the portal/resource templates."""

    return {
        "username": result.get("username") or (
            session.get("username") if session else "unknown"
        ),
        "role": result.get("role") or "unknown",
        "trust_score": result.get("trust_score", 0),
        "risk_score": result.get("risk_score", 100),
        "decision": result.get("decision", "DENY"),
        "reason": result.get("reason", "No policy decision available"),
        "session_status": session.get("status") if session else "NONE",
        "auth_level": session.get("auth_level") if session else "UNKNOWN",
    }


def pep_required(resource_name):
    """
    Policy Enforcement Point decorator.

    Flow for every protected HTTP request:
        Browser -> PEP -> PE/PDP -> GRANT / DENY / REVOKE -> enforcement
    """

    def decorator(view_function):
        @wraps(view_function)
        def wrapped(*args, **kwargs):
            session_id = request.cookies.get(SESSION_COOKIE_NAME)

            if not session_id:
                safe_log_access(
                    username=None,
                    role=None,
                    device_ip=current_client_ip(),
                    resource=resource_name,
                    result="DENY",
                    reason="No ZTNA session presented",
                )

                return denied(
                    "No verified Zero Trust session. Authenticate through the MFA gateway first.",
                    decision="DENY",
                )

            # ----------------------------------------------------
            # Ask the Policy Engine to re-evaluate THIS request.
            # ----------------------------------------------------
            try:
                result = evaluate_session_access(
                    session_id=session_id,
                    resource=resource_name,
                )
            except TypeError:
                # Supports the positional signature used in the earlier PE.
                result = evaluate_session_access(session_id, resource_name)
            except Exception as error:
                print("[POLICY ENGINE ERROR]", error)

                safe_log_access(
                    username=None,
                    role=None,
                    device_ip=current_client_ip(),
                    resource=resource_name,
                    result="DENY",
                    reason="Policy Engine evaluation failed",
                )

                return denied(
                    "Access cannot be evaluated at this time.",
                    decision="DENY",
                )

            if not isinstance(result, dict):
                result = {
                    "decision": "DENY",
                    "reason": "Invalid Policy Engine response",
                }

            decision = str(result.get("decision", "DENY")).upper()
            reason = result.get("reason") or "No decision reason supplied"

            session = get_session_record(session_id)
            username = result.get("username") or (
                session.get("username") if session else None
            )
            role = result.get("role")
            device_ip = (
                session.get("device_ip")
                if session and session.get("device_ip")
                else current_client_ip()
            )

            # ----------------------------------------------------
            # REVOKE: PE countermanded a previous approval.
            # PA terminates the session; PEP blocks the request.
            # ----------------------------------------------------
            if decision == "REVOKE":
                try:
                    revoke_session(session_id, reason)
                except TypeError:
                    revoke_session(session_id)
                except Exception as error:
                    print("[POLICY ADMINISTRATOR ERROR]", error)

                safe_log_access(
                    username=username,
                    role=role,
                    device_ip=device_ip,
                    resource=resource_name,
                    result="DENY",
                    reason="Session revoked: " + reason,
                )

                return denied(
                    reason,
                    decision="REVOKE",
                    clear_session=True,
                )

            # ----------------------------------------------------
            # DENY: request is not permitted, but an otherwise
            # valid session does not have to be destroyed.
            # Example: Employee -> Finance.
            # ----------------------------------------------------
            if decision != "GRANT":
                safe_log_access(
                    username=username,
                    role=role,
                    device_ip=device_ip,
                    resource=resource_name,
                    result="DENY",
                    reason=reason,
                )

                return denied(
                    reason,
                    decision="DENY",
                )

            # ----------------------------------------------------
            # GRANT: PEP allows the request.
            # ----------------------------------------------------
            touch_session(session_id)

            g.ztna_session_id = session_id
            g.ztna_session = session
            g.ztna_decision = result
            g.ztna_state = build_request_state(result, session)
            g.ztna_permission = get_policy_permission(
                g.ztna_state["role"],
                resource_name,
            )

            safe_log_access(
                username=g.ztna_state["username"],
                role=g.ztna_state["role"],
                device_ip=device_ip,
                resource=resource_name,
                result="ALLOW",
                reason=reason,
            )

            return view_function(*args, **kwargs)

        return wrapped

    return decorator


# ============================================================
# HTML - ACCESS DENIED
# ============================================================

DENIED_PAGE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Zero Trust Access Decision</title>
<style>
body {
    margin: 0;
    font-family: Arial, sans-serif;
    background: #0b1220;
    color: #e5e7eb;
}
.container {
    max-width: 850px;
    margin: 110px auto;
    padding: 0 20px;
}
.box {
    padding: 42px;
    text-align: center;
    background: #450a0a;
    border: 1px solid #ef4444;
    border-radius: 15px;
}
h1 {
    margin-top: 0;
    color: #f87171;
    font-size: 34px;
}
.decision {
    display: inline-block;
    margin-bottom: 18px;
    padding: 7px 12px;
    border-radius: 8px;
    background: #7f1d1d;
    color: #fecaca;
    font-weight: bold;
}
.reason {
    font-size: 18px;
}
.info {
    margin-top: 25px;
    color: #cbd5e1;
}
a {
    display: inline-block;
    margin-top: 18px;
    color: #93c5fd;
}
</style>
</head>
<body>
<div class="container">
<div class="box">

<h1>ACCESS DENIED</h1>
<div class="decision">PDP Decision: {{ decision }}</div>

<p class="reason">{{ reason }}</p>

<p class="info">
This resource is protected by the Zero Trust Policy Enforcement Point.
The request must satisfy the current enterprise policy before access is allowed.
</p>

<a href="{{ mfa_url }}">Authenticate through the MFA Gateway</a>

{% if not clear_session %}
<br>
<a href="/portal">Return to Company Portal</a>
{% endif %}

</div>
</div>
</body>
</html>
"""


# ============================================================
# HTML - COMPANY PORTAL
# ============================================================

PORTAL_PAGE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>ZTNA Company Portal</title>
<style>
body {
    margin: 0;
    font-family: Arial, sans-serif;
    background: #0b1220;
    color: #e5e7eb;
}
.header {
    padding: 28px 40px;
    background: #111827;
    border-bottom: 1px solid #263449;
}
.header h1 {
    margin: 0;
    color: #38bdf8;
}
.header p {
    color: #94a3b8;
}
.container {
    max-width: 1100px;
    margin: 35px auto;
    padding: 0 20px;
}
.identity {
    background: #111827;
    border: 1px solid #263449;
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 30px;
}
.identity-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 15px;
}
.label {
    color: #94a3b8;
    font-size: 13px;
    margin-bottom: 6px;
}
.value {
    font-size: 20px;
    font-weight: bold;
}
.good {
    color: #22c55e;
}
.cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 20px;
}
.card {
    background: #111827;
    border: 1px solid #263449;
    border-radius: 12px;
    padding: 24px;
}
.card h3 {
    color: #38bdf8;
}
.card a {
    display: inline-block;
    margin-top: 10px;
    color: #38bdf8;
    text-decoration: none;
    font-weight: bold;
}
.badge {
    display: inline-block;
    padding: 6px 10px;
    border-radius: 8px;
    font-weight: bold;
    background: #14532d;
    color: #86efac;
}
.note {
    margin-top: 24px;
    padding: 14px 16px;
    background: #0f172a;
    border-radius: 8px;
    color: #cbd5e1;
}
</style>
</head>
<body>

<div class="header">
<h1>Zero Trust Company Portal</h1>
<p>Policy-enforced access to protected company resources</p>
</div>

<div class="container">

<div class="identity">
<h2>Current Zero Trust Decision</h2>

<div class="identity-grid">
<div>
    <div class="label">Username</div>
    <div class="value">{{ state.username }}</div>
</div>

<div>
    <div class="label">Role</div>
    <div class="value">{{ state.role }}</div>
</div>

<div>
    <div class="label">Trust / Confidence</div>
    <div class="value good">{{ state.trust_score }}</div>
</div>

<div>
    <div class="label">Risk Score</div>
    <div class="value">{{ state.risk_score }}</div>
</div>

<div>
    <div class="label">PDP Decision</div>
    <div class="value"><span class="badge">GRANT</span></div>
</div>

<div>
    <div class="label">Session</div>
    <div class="value">{{ state.session_status }}</div>
</div>
</div>

<div class="note">
The Policy Enforcement Point re-evaluates each protected resource request.
A successful login does not automatically authorize every resource.
</div>
</div>

<div class="cards">
<div class="card">
<h3>Documents</h3>
<p>Company policies, files and documentation.</p>
<a href="/documents">Request Documents Access</a>
</div>

<div class="card">
<h3>Employee Directory</h3>
<p>Internal employee directory.</p>
<a href="/directory">Request Directory Access</a>
</div>

<div class="card">
<h3>Projects</h3>
<p>Internal project workspace.</p>
<a href="/projects">Request Projects Access</a>
</div>

<div class="card">
<h3>Finance</h3>
<p>Sensitive finance information.</p>
<a href="/finance">Request Finance Access</a>
</div>

<div class="card">
<h3>User Management</h3>
<p>Administrative identity management.</p>
<a href="/users">Request User Management Access</a>
</div>
{% if state.role == 'admin' %}
<div class="card">
<h3>Admin Dashboard</h3>
<p>Zero Trust administration, sessions, certificates and security status.</p>
<a href="http://192.168.30.10:5000/admin">Open Admin Dashboard</a>
</div>
{% endif %}
</div>

</div>
</body>
</html>
"""


# ============================================================
# HTML - RESOURCE PAGE
# ============================================================

RESOURCE_PAGE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>{{ title }}</title>
<style>
body {
    margin: 0;
    font-family: Arial, sans-serif;
    background: #0b1220;
    color: #e5e7eb;
}
.container {
    max-width: 850px;
    margin: 70px auto;
    padding: 30px;
    background: #111827;
    border: 1px solid #263449;
    border-radius: 12px;
}
h1 {
    color: #38bdf8;
}
.permission {
    color: #22c55e;
    font-weight: bold;
}
.details {
    background: #0f172a;
    padding: 16px;
    border-radius: 8px;
    margin: 20px 0;
}
a {
    color: #38bdf8;
}
</style>
</head>
<body>
<div class="container">

<h1>{{ title }}</h1>

<div class="details">
<p><b>Authenticated User:</b> {{ state.username }}</p>
<p><b>Role:</b> {{ state.role }}</p>
<p><b>Trust / Confidence:</b> {{ state.trust_score }}</p>
<p><b>Risk Score:</b> {{ state.risk_score }}</p>
<p><b>Current PDP Decision:</b> {{ state.decision }}</p>
<p><b>Enterprise Policy:</b> {{ permission }}</p>
<p><b>Decision Reason:</b> {{ state.reason }}</p>
</div>

<p class="permission">
PEP Enforcement: ACCESS GRANTED
</p>

<hr>

{{ content | safe }}

<br><br>
<a href="/portal">Return to Company Portal</a>

</div>
</body>
</html>
"""


# ============================================================
# RESPONSE HELPERS
# ============================================================

def denied(reason, decision="DENY", clear_session=False):
    html = render_template_string(
        DENIED_PAGE,
        reason=reason,
        decision=decision,
        clear_session=clear_session,
        mfa_url=MFA_LOGIN_URL,
    )

    response = make_response(html, 403)

    if clear_session:
        response.delete_cookie(
            SESSION_COOKIE_NAME,
            path="/",
        )

    return response


def protected_resource(title, content):
    return render_template_string(
        RESOURCE_PAGE,
        title=title,
        state=g.ztna_state,
        permission=g.ztna_permission,
        content=content,
    )


# ============================================================
# PUBLIC ROUTES
# ============================================================

@app.route("/")
def home():
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>ZTNA Protected Company Server</title>
    </head>
    <body style="background:#0b1220;color:white;font-family:Arial;padding:60px;">
        <h1>ZTNA Protected Company Server</h1>
        <p>This server is protected by a Zero Trust Policy Enforcement Point.</p>
        <p>Authenticate through the MFA Gateway before requesting company resources.</p>
        <a style="color:#38bdf8;" href="{MFA_LOGIN_URL}">
            Open Zero Trust Identity Gateway
        </a>
    </body>
    </html>
    """


@app.route("/health")
def health():
    return {
        "service": "ZTNA Protected Company Server / PEP",
        "status": "running",
        "ip": SERVER_IP,
        "port": SERVER_PORT,
    }


# ============================================================
# PROTECTED PORTAL
# ============================================================

@app.route("/portal")
@pep_required("portal")
def portal():
    return render_template_string(
        PORTAL_PAGE,
        state=g.ztna_state,
    )


# Compatibility routes from the earlier design.
@app.route("/employee")
@pep_required("portal")
def employee_entry():
    return redirect("/portal")


@app.route("/guest")
@pep_required("portal")
def guest_entry():
    return redirect("/portal")


# ============================================================
# DOCUMENTS
# ============================================================

@app.route("/documents")
@pep_required("documents")
def documents():
    content = """
    <h3>Company Documents</h3>
    <p>Policies, procedures and internal documentation are available here.</p>
    <p>The current request was granted by the enterprise access policy.</p>
    """

    return protected_resource(
        "Company Documents",
        content,
    )


# ============================================================
# DIRECTORY
# ============================================================

@app.route("/directory")
@pep_required("directory")
def directory():
    content = """
    <h3>Employee Directory</h3>
    <p>Internal employee and department contact information.</p>
    <p>The current request was granted by the enterprise access policy.</p>
    """

    return protected_resource(
        "Employee Directory",
        content,
    )


# ============================================================
# PROJECTS
# ============================================================

@app.route("/projects")
@pep_required("projects")
def projects():
    content = """
    <h3>Project Workspace</h3>
    <p>Internal company project information and project workspace.</p>
    <p>The current request was granted by the enterprise access policy.</p>
    """

    return protected_resource(
        "Project Workspace",
        content,
    )


# ============================================================
# FINANCE
# ============================================================

@app.route("/finance")
@pep_required("finance")
def finance():
    content = """
    <h3>Finance Department</h3>
    <p>Confidential financial information.</p>
    <p>The current request satisfied the Finance enterprise access policy.</p>
    """

    return protected_resource(
        "Finance",
        content,
    )


# ============================================================
# USER MANAGEMENT
# ============================================================

@app.route("/users")
@pep_required("users")
def users():
    content = """
    <h3>User Management</h3>
    <p>Administrative identity and user-management functions.</p>
    <p>The current request satisfied the User Management enterprise policy.</p>
    """

    return protected_resource(
        "User Management",
        content,
    )


# ============================================================
# BLOCKED TEST PAGE
# ============================================================

@app.route("/blocked")
def blocked():
    return denied(
        "Access intentionally blocked by Zero Trust policy.",
        decision="DENY",
    )


# ============================================================
# CURRENT IDENTITY / POLICY DEBUG VIEW
# ============================================================

@app.route("/identity")
@pep_required("portal")
def identity():
    state = g.ztna_state
    session = g.ztna_session or {}

    return {
        "verified": True,
        "username": state["username"],
        "role": state["role"],
        "trust_score": state["trust_score"],
        "risk_score": state["risk_score"],
        "pdp_decision": state["decision"],
        "reason": state["reason"],
        "session_status": session.get("status", "UNKNOWN"),
        "auth_level": session.get("auth_level", "UNKNOWN"),
        "pep": "ENFORCED",
    }


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":
    print("=" * 72)
    print("ZTNA PROTECTED COMPANY SERVER / POLICY ENFORCEMENT POINT")
    print("Server:", f"http://{SERVER_IP}:{SERVER_PORT}")
    print("PEP: Every protected resource request is re-evaluated")
    print("PDP: Policy Engine + Policy Administrator")
    print("Session Cookie:", SESSION_COOKIE_NAME)
    print("Decisions: GRANT / DENY / REVOKE")
    print("=" * 72)

    app.run(
        host="0.0.0.0",
        port=SERVER_PORT,
        debug=False,
    )
