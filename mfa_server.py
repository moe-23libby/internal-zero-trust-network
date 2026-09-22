import ssl

from flask import (
    Flask,
    request,
    redirect,
    make_response,
    render_template_string,
)

from database import get_connection
from policy_engine import evaluate_initial_access
from policy_administrator import create_session
from risk_engine import set_failed_login_risk, clear_failed_login_risk

from security_utils import (
    log_access,
    get_account_lock_state,
    register_failed_attempt,
    clear_failed_attempts,
)


# ============================================================
# APPLICATION CONFIGURATION
# ============================================================

app = Flask(__name__)

MFA_PORT = 5050

COMPANY_SERVER_URL = "http://192.168.30.10:8000"

SESSION_COOKIE_NAME = "ztna_session"


# ============================================================
# LOGIN PAGE
# ============================================================

LOGIN_PAGE = """
<!DOCTYPE html>

<html>

<head>

    <meta charset="UTF-8">

    <title>ZTNA Secure Login</title>

    <style>

        body {
            margin: 0;
            font-family: Arial, sans-serif;
            background: #0b1220;
            color: #e5e7eb;
        }

        .container {
            width: 420px;
            margin: 80px auto;
        }

        .box {
            background: #111827;
            border: 1px solid #374151;
            border-radius: 14px;
            padding: 32px;
        }

        h1 {
            margin-top: 0;
            text-align: center;
        }

        .subtitle {
            text-align: center;
            color: #9ca3af;
            margin-bottom: 28px;
        }

        label {
            display: block;
            margin-top: 16px;
            margin-bottom: 6px;
        }

        input {
            width: 100%;
            box-sizing: border-box;
            padding: 12px;
            background: #1f2937;
            color: white;
            border: 1px solid #4b5563;
            border-radius: 7px;
        }

        button {
            width: 100%;
            margin-top: 24px;
            padding: 13px;
            border: 0;
            border-radius: 7px;
            background: #2563eb;
            color: white;
            font-size: 16px;
            cursor: pointer;
        }

        button:hover {
            background: #1d4ed8;
        }

        .info {
            margin-top: 20px;
            color: #9ca3af;
            text-align: center;
            font-size: 13px;
        }

    </style>

</head>

<body>

<div class="container">

    <div class="box">

        <h1>Zero Trust Access</h1>

        <div class="subtitle">
            Certificate + Password + OTP Verification
        </div>

        <form method="POST">

            <label>Username</label>

            <input
                type="text"
                name="username"
                required
                autocomplete="username"
            >

            <label>Password</label>

            <input
                type="password"
                name="password"
                required
                autocomplete="current-password"
            >

            <label>OTP Code</label>

            <input
                type="text"
                name="otp"
                required
                autocomplete="one-time-code"
            >

            <button type="submit">
                Verify Identity
            </button>

        </form>

        <div class="info">
            A trusted client certificate is also required.
        </div>

    </div>

</div>

</body>

</html>
"""


# ============================================================
# RESULT PAGE
# ============================================================

RESULT_PAGE = """
<!DOCTYPE html>

<html>

<head>

    <meta charset="UTF-8">

    <title>ZTNA Decision</title>

    <style>

        body {
            margin: 0;
            font-family: Arial, sans-serif;
            background: #0b1220;
            color: #e5e7eb;
        }

        .container {
            max-width: 700px;
            margin: 90px auto;
            padding: 20px;
        }

        .box {
            padding: 36px;
            border-radius: 14px;
            background: #111827;
            border: 1px solid #374151;
        }

        h1 {
            margin-top: 0;
        }

        .allow {
            color: #22c55e;
        }

        .limited {
            color: #f59e0b;
        }

        .block {
            color: #ef4444;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 24px;
        }

        td {
            padding: 10px;
            border-bottom: 1px solid #374151;
        }

        td:first-child {
            color: #9ca3af;
            width: 40%;
        }

        a {
            display: inline-block;
            margin-top: 24px;
            color: #60a5fa;
        }

    </style>

</head>

<body>

<div class="container">

<div class="box">

    <h1 class="{{ css_class }}">
        {{ decision }}
    </h1>

    <table>

        <tr>
            <td>User</td>
            <td>{{ username }}</td>
        </tr>

        <tr>
            <td>Role</td>
            <td>{{ role }}</td>
        </tr>

        <tr>
            <td>Device IP</td>
            <td>{{ device_ip }}</td>
        </tr>

        <tr>
            <td>Trust Score</td>
            <td>{{ trust_score }}</td>
        </tr>

        <tr>
            <td>Risk Score</td>
            <td>{{ risk_score }}</td>
        </tr>

        <tr>
            <td>Reason</td>
            <td>{{ reason }}</td>
        </tr>

    </table>

    <a href="/login">
        Return to Login
    </a>

</div>

</div>

</body>

</html>
"""


# ============================================================
# DATABASE HELPER
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


# ============================================================
# CLIENT IP
# ============================================================

def get_client_ip():

    forwarded = request.headers.get(
        "X-Forwarded-For",
        ""
    ).strip()

    if forwarded:
        return forwarded.split(",")[0].strip()

    return request.remote_addr or "unknown"


# ============================================================
# USER LOOKUP
# ============================================================

def get_user(username):

    db = None
    cursor = None

    try:

        db = get_connection()

        cursor = db.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT
                id,
                username,
                password,
                role,
                device_ip,
                otp_code,
                created_at
            FROM users
            WHERE username = %s
            LIMIT 1
            """,
            (
                username,
            )
        )

        return cursor.fetchone()

    except Exception as error:

        print(
            "[GET USER ERROR]",
            error
        )

        return None

    finally:

        close_database(
            cursor,
            db
        )


# ============================================================
# ACTIVE DEVICE CERTIFICATE
# ============================================================

def get_active_certificate(username):

    db = None
    cursor = None

    try:

        db = get_connection()

        cursor = db.cursor(
            dictionary=True
        )

        cursor.execute(
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
            WHERE username = %s
              AND status = 'ACTIVE'
            ORDER BY id DESC
            LIMIT 1
            """,
            (
                username,
            )
        )

        return cursor.fetchone()

    except Exception as error:

        print(
            "[CERTIFICATE LOOKUP ERROR]",
            error
        )

        return None

    finally:

        close_database(
            cursor,
            db
        )


# ============================================================
# MFA LOG
# ============================================================

def save_mfa_log(
    username,
    role,
    device_ip,
    trust_score,
    threat_level,
    decision,
    mfa_status,
    reason
):

    db = None
    cursor = None

    try:

        db = get_connection()
        cursor = db.cursor()

        cursor.execute(
            """
            INSERT INTO mfa_logs
            (
                username,
                role,
                device_ip,
                trust_score,
                threat_level,
                decision,
                mfa_status,
                reason,
                timestamp
            )
            VALUES
            (
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                NOW()
            )
            """,
            (
                username,
                role,
                device_ip,
                trust_score,
                threat_level,
                decision,
                mfa_status,
                reason
            )
        )

        db.commit()

    except Exception as error:

        print(
            "[MFA LOG ERROR]",
            error
        )

    finally:

        close_database(
            cursor,
            db
        )


# ============================================================
# DEVICE TRUST
# ============================================================

def update_device_trust(
    device_ip,
    device_name,
    role,
    trust_score,
    risk_level,
    status
):

    db = None
    cursor = None

    try:

        db = get_connection()
        cursor = db.cursor()

        cursor.execute(
            """
            INSERT INTO device_trust
            (
                device_ip,
                device_name,
                role,
                trust_score,
                risk_level,
                status,
                timestamp
            )
            VALUES
            (
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                NOW()
            )
            ON DUPLICATE KEY UPDATE

                device_name = VALUES(device_name),
                role = VALUES(role),
                trust_score = VALUES(trust_score),
                risk_level = VALUES(risk_level),
                status = VALUES(status),
                timestamp = NOW()
            """,
            (
                device_ip,
                device_name,
                role,
                trust_score,
                risk_level,
                status
            )
        )

        db.commit()

    except Exception as error:

        print(
            "[DEVICE TRUST ERROR]",
            error
        )

    finally:

        close_database(
            cursor,
            db
        )


# ============================================================
# ENFORCEMENT LOG
# ============================================================

def save_enforcement(
    device_ip,
    action,
    destination_ip,
    destination_port,
    reason
):

    db = None
    cursor = None

    try:

        db = get_connection()
        cursor = db.cursor()

        cursor.execute(
            """
            INSERT INTO enforcement_logs
            (
                device_ip,
                action,
                destination_ip,
                destination_port,
                reason,
                timestamp
            )
            VALUES
            (
                %s,
                %s,
                %s,
                %s,
                %s,
                NOW()
            )
            """,
            (
                device_ip,
                action,
                destination_ip,
                destination_port,
                reason
            )
        )

        db.commit()

    except Exception as error:

        print(
            "[ENFORCEMENT LOG ERROR]",
            error
        )

    finally:

        close_database(
            cursor,
            db
        )


# ============================================================
# ACCESS STATE
# ============================================================

def update_access_state(
    username,
    role,
    device_name,
    trust_score,
    risk_score,
    decision,
    step_up_required,
    reason
):

    db = None
    cursor = None

    try:

        db = get_connection()
        cursor = db.cursor()

        cursor.execute(
            """
            INSERT INTO access_state
            (
                username,
                role,
                device_name,
                trust_score,
                risk_score,
                decision,
                step_up_required,
                quarantine_status,
                reason
            )
            VALUES
            (
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                0,
                %s
            )

            ON DUPLICATE KEY UPDATE

                role = VALUES(role),
                device_name = VALUES(device_name),
                trust_score = VALUES(trust_score),
                risk_score = VALUES(risk_score),
                decision = VALUES(decision),
                step_up_required = VALUES(step_up_required),

                /*
                Quarantine is no longer used as a visible
                access-control feature in the new design.
                */

                quarantine_status = 0,

                reason = VALUES(reason)
            """,
            (
                username,
                role,
                device_name,
                trust_score,
                risk_score,
                decision,
                step_up_required,
                reason
            )
        )

        db.commit()

    except Exception as error:

        print(
            "[ACCESS STATE ERROR]",
            error
        )

    finally:

        close_database(
            cursor,
            db
        )


# ============================================================
# RISK LEVEL
# ============================================================

def get_risk_level(trust_score):

    if trust_score >= 80:
        return "Low"

    if trust_score >= 60:
        return "Medium"

    if trust_score >= 40:
        return "High"

    return "Critical"


# ============================================================
# RECORD SECURITY RESULT
# ============================================================

def record_security_result(
    username,
    role,
    device_ip,
    device_name,
    trust_score,
    risk_score,
    decision,
    mfa_status,
    reason,
    step_up_required=0
):

    threat_level = get_risk_level(
        trust_score
    )

    save_mfa_log(
        username=username,
        role=role,
        device_ip=device_ip,
        trust_score=trust_score,
        threat_level=threat_level,
        decision=decision,
        mfa_status=mfa_status,
        reason=reason
    )

    update_device_trust(
        device_ip=device_ip,
        device_name=device_name,
        role=role,
        trust_score=trust_score,
        risk_level=threat_level,
        status=decision
    )

    update_access_state(
        username=username,
        role=role,
        device_name=device_name,
        trust_score=trust_score,
        risk_score=risk_score,
        decision=decision,
        step_up_required=step_up_required,
        reason=reason
    )

    save_enforcement(
        device_ip=device_ip,
        action=decision,
        destination_ip="192.168.30.10",
        destination_port=8000,
        reason=reason
    )


# ============================================================
# REVOKE EXISTING USER SESSIONS
# ============================================================

def revoke_existing_sessions(username):

    db = None
    cursor = None

    try:

        db = get_connection()
        cursor = db.cursor()

        cursor.execute(
            """
            UPDATE access_sessions

            SET
                status = 'REVOKED',
                revoked_at = NOW()

            WHERE username = %s
              AND status = 'ACTIVE'
            """,
            (
                username,
            )
        )

        db.commit()

    except Exception as error:

        print(
            "[SESSION REVOKE ERROR]",
            error
        )

    finally:

        close_database(
            cursor,
            db
        )


# ============================================================
# REDIRECT TO COMPANY SERVER
# ============================================================

def redirect_to_company(session_id):

    if not session_id:
        return (
            "Unable to create ZTNA session",
            500
        )

    response = make_response(
        redirect(
            COMPANY_SERVER_URL
            + "/portal"
        )
    )

    response.set_cookie(
        SESSION_COOKIE_NAME,
        session_id,

        # Current Company Server uses HTTP.
        # Therefore Secure=True cannot be used yet.
        httponly=True,
        samesite="Lax",
        path="/"
    )

    return response


# ============================================================
# RESULT DISPLAY
# ============================================================

def show_result(
    username,
    role,
    device_ip,
    trust_score,
    risk_score,
    decision,
    reason,
    status_code=403
):

    if decision == "ALLOW":
        css_class = "allow"

    elif decision == "LIMITED":
        css_class = "limited"

    else:
        css_class = "block"

    html = render_template_string(
        RESULT_PAGE,
        username=username,
        role=role,
        device_ip=device_ip,
        trust_score=trust_score,
        risk_score=risk_score,
        decision=decision,
        reason=reason,
        css_class=css_class
    )

    return html, status_code


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    return redirect(
        "/login"
    )


# ============================================================
# LOGIN
# ============================================================

@app.route(
    "/login",
    methods=[
        "GET",
        "POST"
    ]
)
def login():

    # --------------------------------------------------------
    # GET LOGIN PAGE
    # --------------------------------------------------------

    if request.method == "GET":

        return render_template_string(
            LOGIN_PAGE
        )

    # --------------------------------------------------------
    # READ FORM
    # --------------------------------------------------------

    username = request.form.get(
        "username",
        ""
    ).strip()

    password = request.form.get(
        "password",
        ""
    ).strip()

    otp = request.form.get(
        "otp",
        ""
    ).strip()

    device_ip = get_client_ip()
   # Local SOC administrator uses the configured Admin workstation identity.
    if username == "admin" and device_ip in ("127.0.0.1", "::1"):
    	device_ip = "192.168.30.10"

    # --------------------------------------------------------
    # BASIC VALIDATION
    # --------------------------------------------------------

    if not username:

        log_access(
            username=None,
            role=None,
            device_ip=device_ip,
            resource="MFA Login",
            action="LOGIN",
            result="DENY",
            reason="Username not provided"
        )

        return (
            "Username is required",
            400
        )

    # --------------------------------------------------------
    # USER LOOKUP
    # --------------------------------------------------------

    user = get_user(
        username
    )

    # --------------------------------------------------------
    # UNKNOWN USER
    # --------------------------------------------------------

    if user is None:

        save_mfa_log(
            username=username,
            role="unknown",
            device_ip=device_ip,
            trust_score=0,
            threat_level="Critical",
            decision="BLOCK",
            mfa_status="FAILED",
            reason="Unknown user"
        )

        log_access(
            username=username,
            role="unknown",
            device_ip=device_ip,
            resource="MFA Login",
            action="LOGIN",
            result="DENY",
            reason="Unknown username"
        )

        return show_result(
            username=username,
            role="unknown",
            device_ip=device_ip,
            trust_score=0,
            risk_score=100,
            decision="BLOCK",
            reason="Unknown user",
            status_code=403
        )

    role = user["role"]

    # --------------------------------------------------------
    # CHECK ACCOUNT LOCK
    # --------------------------------------------------------

    lock_state = get_account_lock_state(
        username
    )

    if (
        lock_state is not None
        and
        lock_state["account_status"]
        == "LOCKED"
    ):

        log_access(
            username=username,
            role=role,
            device_ip=device_ip,
            resource="MFA Login",
            action="LOGIN",
            result="DENY",
            reason=(
                "Account temporarily locked"
            )
        )

        record_security_result(
            username=username,
            role=role,
            device_ip=device_ip,
            device_name=(
                username
                + "-device"
            ),
            trust_score=20,
            risk_score=80,
            decision="BLOCK",
            mfa_status="LOCKED",
            reason=(
                "Account temporarily locked "
                "after repeated failed login attempts"
            )
        )

        return show_result(
            username=username,
            role=role,
            device_ip=device_ip,
            trust_score=20,
            risk_score=80,
            decision="BLOCK",
            reason=(
                "Account temporarily locked. "
                "Contact the administrator or "
                "wait 15 minutes."
            ),
            status_code=403
        )

    # --------------------------------------------------------
    # PASSWORD CHECK
    # --------------------------------------------------------

    if user["password"] != password:

        attempts, locked = (
            register_failed_attempt(
                username=username,
                source_ip=device_ip,
                reason="Invalid password"
            )
        )

        set_failed_login_risk(username, attempts)

        log_access(
            username=username,
            role=role,
            device_ip=device_ip,
            resource="MFA Login",
            action="LOGIN",
            result="DENY",
            reason=(
                "Invalid password - attempt "
                + str(attempts)
            )
        )

        if locked:

            record_security_result(
                username=username,
                role=role,
                device_ip=device_ip,
                device_name=(
                    username
                    + "-device"
                ),
                trust_score=20,
                risk_score=80,
                decision="BLOCK",
                mfa_status="LOCKED",
                reason=(
                    "Account locked after "
                    "multiple failed passwords"
                )
            )

            return show_result(
                username=username,
                role=role,
                device_ip=device_ip,
                trust_score=20,
                risk_score=80,
                decision="BLOCK",
                reason=(
                    "Too many failed login "
                    "attempts. Account has "
                    "been temporarily locked."
                ),
                status_code=403
            )

        record_security_result(
            username=username,
            role=role,
            device_ip=device_ip,
            device_name=(
                username
                + "-device"
            ),
            trust_score=20,
            risk_score=80,
            decision="BLOCK",
            mfa_status="FAILED",
            reason=(
                "Invalid password - attempt "
                + str(attempts)
            )
        )

        return show_result(
            username=username,
            role=role,
            device_ip=device_ip,
            trust_score=20,
            risk_score=80,
            decision="BLOCK",
            reason=(
                "Invalid password. Failed attempt "
                + str(attempts)
                + " of 3."
            ),
            status_code=403
        )

    # --------------------------------------------------------
    # OTP CHECK
    # --------------------------------------------------------

    if user["otp_code"] != otp:

        attempts, locked = (
            register_failed_attempt(
                username=username,
                source_ip=device_ip,
                reason="Invalid OTP"
            )
        )

        set_failed_login_risk(username, attempts)

        log_access(
            username=username,
            role=role,
            device_ip=device_ip,
            resource="MFA Login",
            action="LOGIN",
            result="DENY",
            reason=(
                "Invalid OTP - attempt "
                + str(attempts)
            )
        )

        if locked:

            record_security_result(
                username=username,
                role=role,
                device_ip=device_ip,
                device_name=(
                    username
                    + "-device"
                ),
                trust_score=30,
                risk_score=70,
                decision="BLOCK",
                mfa_status="LOCKED",
                reason=(
                    "Account locked after "
                    "multiple failed OTP attempts"
                )
            )

            return show_result(
                username=username,
                role=role,
                device_ip=device_ip,
                trust_score=30,
                risk_score=70,
                decision="BLOCK",
                reason=(
                    "Too many failed "
                    "authentication attempts. "
                    "Account temporarily locked."
                ),
                status_code=403
            )

        record_security_result(
            username=username,
            role=role,
            device_ip=device_ip,
            device_name=(
                username
                + "-device"
            ),
            trust_score=40,
            risk_score=60,
            decision="BLOCK",
            mfa_status="FAILED",
            reason=(
                "Invalid OTP - attempt "
                + str(attempts)
            )
        )

        return show_result(
            username=username,
            role=role,
            device_ip=device_ip,
            trust_score=40,
            risk_score=60,
            decision="BLOCK",
            reason=(
                "Invalid OTP. Failed attempt "
                + str(attempts)
                + " of 3."
            ),
            status_code=403
        )

    # --------------------------------------------------------
    # ATTACKER ROLE
    # --------------------------------------------------------

    if role == "attacker":

        clear_failed_attempts(
            username
        )

        record_security_result(
            username=username,
            role=role,
            device_ip=device_ip,
            device_name="Untrusted Device",
            trust_score=0,
            risk_score=100,
            decision="BLOCK",
            mfa_status="BLOCKED",
            reason=(
                "Attacker role is not "
                "authorized for company access"
            )
        )

        log_access(
            username=username,
            role=role,
            device_ip=device_ip,
            resource="MFA Login",
            action="LOGIN",
            result="DENY",
            reason="Attacker role blocked"
        )

        return show_result(
            username=username,
            role=role,
            device_ip=device_ip,
            trust_score=0,
            risk_score=100,
            decision="BLOCK",
            reason=(
                "This identity is not "
                "authorized to access "
                "company resources."
            ),
            status_code=403
        )

    # --------------------------------------------------------
    # REGISTERED CERTIFICATE CHECK
    # --------------------------------------------------------

    certificate = get_active_certificate(
        username
    )

    if certificate is None:

        record_security_result(
            username=username,
            role=role,
            device_ip=device_ip,
            device_name=(
                username
                + "-device"
            ),
            trust_score=30,
            risk_score=70,
            decision="BLOCK",
            mfa_status="FAILED",
            reason=(
                "No active registered "
                "device certificate"
            )
        )

        log_access(
            username=username,
            role=role,
            device_ip=device_ip,
            resource="MFA Login",
            action="LOGIN",
            result="DENY",
            reason=(
                "Registered device certificate "
                "is missing or revoked"
            )
        )

        return show_result(
            username=username,
            role=role,
            device_ip=device_ip,
            trust_score=30,
            risk_score=70,
            decision="BLOCK",
            reason=(
                "Device certificate is "
                "not registered or has "
                "been revoked."
            ),
            status_code=403
        )

    device_name = (
        certificate.get("device_name")
        or certificate.get("certificate_cn")
        or (
            username
            + "-device"
        )
    )

    # --------------------------------------------------------
    # POLICY DECISION POINT (PE + PA)
    # --------------------------------------------------------

    # The TLS server is configured with ssl.CERT_REQUIRED, so a
    # CA-signed client certificate is required before this route
    # can be reached. The application also checks that the user
    # has an ACTIVE registered certificate above.
    #
    # Note: this prototype does not yet cryptographically bind the
    # exact presented client-certificate serial/CN to the username.

    # Successful password + OTP + active certificate: recover temporary
    # authentication-failure risk before the new PE decision.
    clear_failed_login_risk(username)

    policy_result = evaluate_initial_access(
        username=username,
        device_ip=device_ip,
        resource="portal",
        mfa_verified=True,
        certificate_verified=True
    )

    trust_score = policy_result.get("trust_score", 0)
    risk_score = policy_result.get("risk_score", 100)
    policy_decision = policy_result.get("decision", "DENY")
    reason = policy_result.get(
        "reason",
        "Policy Engine did not grant access"
    )

    if policy_decision != "GRANT":

        record_security_result(
            username=username,
            role=role,
            device_ip=device_ip,
            device_name=device_name,
            trust_score=trust_score,
            risk_score=risk_score,
            decision="BLOCK",
            mfa_status="DENIED",
            reason=reason
        )

        log_access(
            username=username,
            role=role,
            device_ip=device_ip,
            resource="MFA Login",
            action="LOGIN",
            result="DENY",
            reason=(
                "Policy Engine decision: "
                + policy_decision
                + " - "
                + reason
            )
        )

        return show_result(
            username=username,
            role=role,
            device_ip=device_ip,
            trust_score=trust_score,
            risk_score=risk_score,
            decision="BLOCK",
            reason=reason,
            status_code=403
        )

    # --------------------------------------------------------
    # POLICY ADMINISTRATOR - CREATE SESSION
    # --------------------------------------------------------

    session_id = create_session(
        username=username,
        device_ip=device_ip,
        mfa_verified=True,
        certificate_verified=True
    )

    if not session_id:

        record_security_result(
            username=username,
            role=role,
            device_ip=device_ip,
            device_name=device_name,
            trust_score=trust_score,
            risk_score=risk_score,
            decision="BLOCK",
            mfa_status="ERROR",
            reason="Policy Administrator could not create session"
        )

        return show_result(
            username=username,
            role=role,
            device_ip=device_ip,
            trust_score=trust_score,
            risk_score=risk_score,
            decision="BLOCK",
            reason="Unable to create ZTNA session",
            status_code=500
        )

    # Existing tables/dashboard use ALLOW/BLOCK terminology, while
    # policy_decisions uses the NIST-style GRANT/DENY/REVOKE terms.
    record_security_result(
        username=username,
        role=role,
        device_ip=device_ip,
        device_name=device_name,
        trust_score=trust_score,
        risk_score=risk_score,
        decision="ALLOW",
        mfa_status="SUCCESS",
        reason=reason
    )

    clear_failed_attempts(
        username
    )

    log_access(
        username=username,
        role=role,
        device_ip=device_ip,
        resource="MFA Login",
        action="LOGIN",
        result="ALLOW",
        reason=(
            "PE=GRANT; PA created ACTIVE session; "
            + reason
        )
    )

    return redirect_to_company(
        session_id
    )


# ============================================================
# STEP-UP MFA
# ============================================================

@app.route(
    "/step-up",
    methods=[
        "GET",
        "POST"
    ]
)
def step_up():

    if request.method == "GET":

        return """
        <!DOCTYPE html>

        <html>

        <head>
            <title>ZTNA Step-Up MFA</title>
        </head>

        <body style="
            background:#0b1220;
            color:white;
            font-family:Arial;
        ">

        <div style="
            max-width:420px;
            margin:100px auto;
            background:#111827;
            padding:30px;
            border-radius:12px;
        ">

        <h2>
            Step-Up Authentication
        </h2>

        <p>
            Additional verification is required.
        </p>

        <form method="POST">

            <p>Username</p>

            <input
                name="username"
                required
                style="
                    width:100%;
                    padding:10px;
                    box-sizing:border-box;
                "
            >

            <p>OTP</p>

            <input
                name="otp"
                required
                style="
                    width:100%;
                    padding:10px;
                    box-sizing:border-box;
                "
            >

            <button
                type="submit"
                style="
                    margin-top:20px;
                    padding:10px 20px;
                "
            >
                Verify
            </button>

        </form>

        </div>

        </body>

        </html>
        """

    username = request.form.get(
        "username",
        ""
    ).strip()

    otp = request.form.get(
        "otp",
        ""
    ).strip()

    device_ip = get_client_ip()

    user = get_user(
        username
    )

    if user is None:

        return (
            "Unknown user",
            403
        )

    lock_state = get_account_lock_state(
        username
    )

    if (
        lock_state is not None
        and
        lock_state["account_status"]
        == "LOCKED"
    ):

        return (
            "Account is currently locked",
            403
        )

    if user["otp_code"] != otp:

        attempts, locked = (
            register_failed_attempt(
                username=username,
                source_ip=device_ip,
                reason=(
                    "Invalid step-up OTP"
                )
            )
        )

        log_access(
            username=username,
            role=user["role"],
            device_ip=device_ip,
            resource="Step-Up MFA",
            action="LOGIN",
            result="DENY",
            reason=(
                "Invalid step-up OTP"
            )
        )

        set_failed_login_risk(username, attempts)

        if locked:

            return (
                "Too many failed attempts. "
                "Account temporarily locked.",
                403
            )

        return (
            "Invalid OTP",
            403
        )

    certificate = get_active_certificate(
        username
    )

    if certificate is None:

        return (
            "No active registered certificate",
            403
        )

    db = None
    cursor = None

    try:

        db = get_connection()
        cursor = db.cursor()

        cursor.execute(
            """
            UPDATE access_state

            SET
                trust_score = 85,
                risk_score = 15,
                decision = 'ALLOW',
                step_up_required = 0,
                quarantine_status = 0,
                reason =
                    'Step-up MFA successfully completed'

            WHERE username = %s
            """,
            (
                username,
            )
        )

        db.commit()

    except Exception as error:

        print(
            "[STEP-UP ERROR]",
            error
        )

        return (
            "Unable to update access state",
            500
        )

    finally:

        close_database(
            cursor,
            db
        )

    clear_failed_attempts(
        username
    )
    clear_failed_login_risk(username)

    log_access(
        username=username,
        role=user["role"],
        device_ip=device_ip,
        resource="Step-Up MFA",
        action="LOGIN",
        result="ALLOW",
        reason=(
            "Step-up MFA successfully completed"
        )
    )

    # Re-evaluate access after successful step-up verification.
    policy_result = evaluate_initial_access(
        username=username,
        device_ip=device_ip,
        resource="portal",
        mfa_verified=True,
        certificate_verified=True
    )

    if policy_result.get("decision") != "GRANT":
        return show_result(
            username=username,
            role=user["role"],
            device_ip=device_ip,
            trust_score=policy_result.get("trust_score", 0),
            risk_score=policy_result.get("risk_score", 100),
            decision="BLOCK",
            reason=policy_result.get(
                "reason",
                "Policy Engine denied access"
            ),
            status_code=403
        )

    session_id = create_session(
        username=username,
        device_ip=device_ip,
        mfa_verified=True,
        certificate_verified=True
    )

    if not session_id:
        return (
            "Unable to create ZTNA session",
            500
        )

    return redirect_to_company(
        session_id
    )


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/health")
def health():

    return {
        "service": "ZTNA MFA Server",
        "status": "healthy",
        "port": MFA_PORT
    }


# ============================================================
# START HTTPS / MUTUAL TLS SERVER
# ============================================================

if __name__ == "__main__":

    context = ssl.create_default_context(
        ssl.Purpose.CLIENT_AUTH
    )

    context.load_cert_chain(
        certfile=(
            "certs/server/"
            "mfa-server.crt"
        ),
        keyfile=(
            "certs/server/"
            "mfa-server.key"
        )
    )

    context.load_verify_locations(
        cafile=(
            "certs/ca/"
            "ca.crt"
        )
    )

    context.verify_mode = (
        ssl.CERT_REQUIRED
    )

    print(
        "[ZTNA] MFA Server starting"
    )

    print(
        "[ZTNA] HTTPS port:",
        MFA_PORT
    )

    print(
        "[ZTNA] Client certificate required"
    )

    print(
        "[ZTNA] Failed-login lock threshold: 3"
    )

    app.run(
        host="0.0.0.0",
        port=MFA_PORT,
        ssl_context=context,
        debug=False
    )
