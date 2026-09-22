#!/usr/bin/env python3
import os
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash
)

from database import get_connection
from timeline import log_timeline
from security_utils import admin_unlock_user


app = Flask(__name__)

app.secret_key = os.environ["ZTNA_DASHBOARD_SECRET"]
SESSION_COOKIE_NAME = "ztna_session"


# ============================================================
# DATABASE HELPERS
# ============================================================

def query_all(sql, params=None):
    db = get_connection()
    cursor = db.cursor(dictionary=True)

    try:
        cursor.execute(
            sql,
            params or ()
        )

        return cursor.fetchall()

    finally:
        cursor.close()
        db.close()


def query_one(sql, params=None):
    db = get_connection()
    cursor = db.cursor(dictionary=True)

    try:
        cursor.execute(
            sql,
            params or ()
        )

        return cursor.fetchone()

    finally:
        cursor.close()
        db.close()


def execute_query(sql, params=None):
    db = get_connection()
    cursor = db.cursor()

    try:
        cursor.execute(
            sql,
            params or ()
        )

        db.commit()

        return cursor.rowcount

    except Exception:
        db.rollback()
        raise

    finally:
        cursor.close()
        db.close()


# ============================================================
# ADMIN SESSION CHECK
# ============================================================

def get_admin_identity():

    session_id = request.cookies.get(
        SESSION_COOKIE_NAME
    )

    if not session_id:
        return None

    return query_one(
        """
        SELECT
            s.username,
            s.device_ip,
            s.status,
            a.role,
            a.decision,
            a.trust_score,
            a.risk_score
        FROM access_sessions s

        JOIN access_state a
          ON a.username = s.username

        WHERE s.session_id = %s
          AND s.status = 'ACTIVE'
          AND a.role = 'admin'
          AND a.decision = 'ALLOW'

        LIMIT 1
        """,
        (
            session_id,
        )
    )


# ============================================================
# OVERVIEW
# ============================================================

@app.route("/")
def overview():

    trusted_devices = query_one(
        """
        SELECT COUNT(*) AS total
        FROM access_state
        WHERE trust_score >= 80
          AND decision IN ('ALLOW', 'LIMITED')
        """
    )["total"]

    active_sessions = query_one(
        """
        SELECT COUNT(*) AS total
        FROM access_sessions
        WHERE status = 'ACTIVE'
        """
    )["total"]

    attacks_today = query_one(
        """
        SELECT COUNT(*) AS total
        FROM attack_logs
        WHERE DATE(timestamp) = CURDATE()
        """
    )["total"]

    open_alerts = query_one(
        """
        SELECT COUNT(*) AS total
        FROM security_alerts
        WHERE status = 'OPEN'
        """
    )["total"]

    locked_accounts = query_one(
        """
        SELECT COUNT(*) AS total
        FROM users
        WHERE account_status = 'LOCKED'
        """
    )["total"]

    access_states = query_all(
        """
        SELECT
            username,
            role,
            device_name,
            trust_score,
            risk_score,
            decision,
            step_up_required,
            reason,
            updated_at
        FROM access_state
        ORDER BY
            risk_score DESC,
            updated_at DESC
        """
    )

    latest_attack = query_one(
        """
        SELECT *
        FROM attack_logs
        ORDER BY timestamp DESC
        LIMIT 1
        """
    )

    recent_attacks = query_all(
        """
        SELECT *
        FROM attack_logs
        ORDER BY timestamp DESC
        LIMIT 8
        """
    )

    recent_history = query_all(
        """
        SELECT *
        FROM access_history
        ORDER BY timestamp DESC
        LIMIT 8
        """
    )

    recent_alerts = query_all(
        """
        SELECT *
        FROM security_alerts
        ORDER BY created_at DESC
        LIMIT 8
        """
    )

    timeline = query_all(
        """
        SELECT *
        FROM incident_timeline
        ORDER BY timestamp DESC
        LIMIT 10
        """
    )

    return render_template(
        "dashboard.html",
        page="overview",
        trusted_devices=trusted_devices,
        active_sessions=active_sessions,
        attacks_today=attacks_today,
        open_alerts=open_alerts,
        locked_accounts=locked_accounts,
        access_states=access_states,
        latest_attack=latest_attack,
        recent_attacks=recent_attacks,
        recent_history=recent_history,
        recent_alerts=recent_alerts,
        timeline=timeline
    )


# ============================================================
# ACCESS / TRUST / RISK
# ============================================================

@app.route("/access")
def access():

    access_states = query_all(
        """
        SELECT
            username,
            role,
            device_name,
            trust_score,
            risk_score,
            decision,
            step_up_required,
            reason,
            updated_at
        FROM access_state
        ORDER BY
            risk_score DESC,
            updated_at DESC
        """
    )

    return render_template(
        "dashboard.html",
        page="access",
        access_states=access_states
    )


# ============================================================
# ACCESS HISTORY
# ============================================================

@app.route("/history")
def history():

    access_history = query_all(
        """
        SELECT
            id,
            username,
            role,
            device_ip,
            resource,
            action,
            result,
            reason,
            timestamp
        FROM access_history
        ORDER BY timestamp DESC
        LIMIT 200
        """
    )

    return render_template(
        "dashboard.html",
        page="history",
        access_history=access_history
    )


# ============================================================
# DEVICES / CERTIFICATES
# ============================================================

@app.route("/devices")
def devices():

    certificates = query_all(
        """
        SELECT
            id,
            username,
            certificate_cn,
            certificate_serial,
            device_name,
            status,
            created_at,
            revoked_at
        FROM device_certificates
        ORDER BY id DESC
        """
    )

    return render_template(
        "dashboard.html",
        page="devices",
        certificates=certificates
    )


# ============================================================
# ATTACK MONITORING
# ============================================================

@app.route("/threats")
def threats():

    attacks = query_all(
        """
        SELECT *
        FROM attack_logs
        ORDER BY timestamp DESC
        LIMIT 200
        """
    )

    return render_template(
        "dashboard.html",
        page="threats",
        attacks=attacks
    )


# ============================================================
# SECURITY ALERTS
# ============================================================

@app.route("/alerts")
def alerts():

    security_alerts = query_all(
        """
        SELECT
            id,
            username,
            source_ip,
            alert_type,
            severity,
            description,
            status,
            created_at,
            resolved_at,
            resolved_by
        FROM security_alerts
        ORDER BY created_at DESC
        LIMIT 200
        """
    )

    return render_template(
        "dashboard.html",
        page="alerts",
        security_alerts=security_alerts
    )


# ============================================================
# INCIDENTS
# ============================================================

@app.route("/incidents")
def incidents():

    timeline = query_all(
        """
        SELECT *
        FROM incident_timeline
        ORDER BY timestamp DESC
        LIMIT 200
        """
    )

    enforcement = query_all(
        """
        SELECT *
        FROM enforcement_logs
        ORDER BY timestamp DESC
        LIMIT 100
        """
    )

    return render_template(
        "dashboard.html",
        page="incidents",
        timeline=timeline,
        enforcement=enforcement
    )


# ============================================================
# ADMIN
# ============================================================

@app.route("/admin")
def admin():

    admin_user = get_admin_identity()

    if admin_user is None:
        return (
            "Admin ZTNA session required",
            403
        )

    sessions = query_all(
        """
        SELECT *
        FROM access_sessions
        ORDER BY created_at DESC
        LIMIT 100
        """
    )

    certificates = query_all(
        """
        SELECT *
        FROM device_certificates
        ORDER BY id DESC
        """
    )

    blocked_users = query_all(
        """
        SELECT
            id,
            username,
            role,
            device_ip,
            failed_attempts,
            account_status,
            locked_until
        FROM users
        WHERE account_status = 'LOCKED'
        ORDER BY username
        """
    )

    admin_alerts = query_all(
        """
        SELECT
            id,
            username,
            source_ip,
            alert_type,
            severity,
            description,
            status,
            created_at
        FROM security_alerts
        WHERE status = 'OPEN'
        ORDER BY created_at DESC
        LIMIT 50
        """
    )

    return render_template(
        "dashboard.html",
        page="admin",
        sessions=sessions,
        certificates=certificates,
        blocked_users=blocked_users,
        admin_alerts=admin_alerts,
        admin_user=admin_user
    )


# ============================================================
# ADMIN ACTION - REVOKE SESSION
# ============================================================

@app.route(
    "/admin/revoke-session/<int:session_db_id>",
    methods=["POST"]
)
def revoke_session(session_db_id):

    admin_user = get_admin_identity()

    if admin_user is None:
        return (
            "Admin required",
            403
        )

    session = query_one(
        """
        SELECT *
        FROM access_sessions
        WHERE id = %s
        """,
        (
            session_db_id,
        )
    )

    if session is None:
        return (
            "Session not found",
            404
        )

    if session["username"] == admin_user["username"]:

        flash(
            "The current administrator session cannot "
            "be revoked from this page."
        )

        return redirect(
            url_for("admin")
        )

    execute_query(
        """
        UPDATE access_sessions
        SET
            status = 'REVOKED',
            revoked_at = NOW()
        WHERE id = %s
        """,
        (
            session_db_id,
        )
    )

    log_timeline(
        event_type="SESSION_REVOKED",
        username=session["username"],
        source_ip=session.get("device_ip"),
        description=(
            "User session revoked by administrator "
            + admin_user["username"]
        ),
        severity="High"
    )

    flash(
        "Session revoked successfully."
    )

    return redirect(
        url_for("admin")
    )


# ============================================================
# ADMIN ACTION - REVOKE CERTIFICATE
# ============================================================

@app.route(
    "/admin/revoke-certificate/<int:certificate_id>",
    methods=["POST"]
)
def revoke_certificate(certificate_id):

    admin_user = get_admin_identity()

    if admin_user is None:
        return (
            "Admin required",
            403
        )

    certificate = query_one(
        """
        SELECT *
        FROM device_certificates
        WHERE id = %s
        """,
        (
            certificate_id,
        )
    )

    if certificate is None:
        return (
            "Certificate not found",
            404
        )

    if certificate["username"] == admin_user["username"]:

        flash(
            "The active administrator certificate "
            "cannot be revoked from this page."
        )

        return redirect(
            url_for("admin")
        )

    execute_query(
        """
        UPDATE device_certificates
        SET
            status = 'REVOKED',
            revoked_at = NOW()
        WHERE id = %s
        """,
        (
            certificate_id,
        )
    )

    execute_query(
        """
        UPDATE access_sessions
        SET
            status = 'REVOKED',
            revoked_at = NOW()
        WHERE username = %s
          AND status = 'ACTIVE'
        """,
        (
            certificate["username"],
        )
    )

    execute_query(
        """
        UPDATE access_state
        SET
            decision = 'BLOCK',
            trust_score = 20,
            risk_score = 80,
            reason = 'Device certificate revoked by administrator'
        WHERE username = %s
        """,
        (
            certificate["username"],
        )
    )

    log_timeline(
        event_type="CERTIFICATE_REVOKED",
        username=certificate["username"],
        source_ip=None,
        description=(
            "Device certificate revoked by administrator "
            + admin_user["username"]
        ),
        severity="Critical"
    )

    flash(
        "Certificate and active sessions revoked successfully."
    )

    return redirect(
        url_for("admin")
    )


# ============================================================
# ADMIN ACTION - UNLOCK USER
# ============================================================

@app.route(
    "/admin/unlock-user/<int:user_id>",
    methods=["POST"]
)
def unlock_user(user_id):

    admin_user = get_admin_identity()

    if admin_user is None:
        return (
            "Admin required",
            403
        )

    user = query_one(
        """
        SELECT
            id,
            username,
            role,
            device_ip,
            failed_attempts,
            account_status
        FROM users
        WHERE id = %s
        LIMIT 1
        """,
        (
            user_id,
        )
    )

    if user is None:
        return (
            "User not found",
            404
        )

    success = admin_unlock_user(
        username=user["username"],
        admin_username=admin_user["username"]
    )

    if not success:
        return (
            "Unable to unlock user",
            500
        )

    log_timeline(
        event_type="ACCOUNT_UNLOCK",
        username=user["username"],
        source_ip=user.get("device_ip"),
        description=(
            "Account unlocked by administrator "
            + admin_user["username"]
        ),
        severity="Info"
    )

    flash(
        user["username"]
        + " unlocked successfully. "
        + "The user must authenticate again."
    )

    return redirect(
        url_for("admin")
    )


# ============================================================
# HEALTH
# ============================================================

@app.route("/health")
def health():

    return {
        "service": "ZTNA Security Dashboard",
        "status": "running",
        "port": 5000
    }


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print(
        "ZTNA Security Dashboard"
    )

    print(
        "http://0.0.0.0:5000"
    )

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
