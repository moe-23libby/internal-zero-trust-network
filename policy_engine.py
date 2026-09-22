from database import get_connection
from risk_engine import get_current_identity_risk


def _close(cursor, connection):
    try:
        if cursor is not None:
            cursor.close()
    finally:
        if connection is not None:
            connection.close()


def query_one(sql, params=()):
    connection = None
    cursor = None
    try:
        connection = get_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(sql, params)
        return cursor.fetchone()
    finally:
        _close(cursor, connection)


def save_decision(username, role, resource, decision, trust_score, risk_score, reason):
    connection = None
    cursor = None
    try:
        connection = get_connection()
        cursor = connection.cursor()
        cursor.execute(
            """
            INSERT INTO policy_decisions
                (username, role, resource, decision,
                 trust_score, risk_score, reason, timestamp)
            VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
            """,
            (
                username,
                role,
                resource,
                decision,
                trust_score,
                risk_score,
                reason,
            ),
        )
        connection.commit()
    except Exception as error:
        print("[PE LOG ERROR]", error)
    finally:
        _close(cursor, connection)


def get_user(username):
    return query_one(
        "SELECT * FROM users WHERE username = %s LIMIT 1",
        (username,),
    )


def get_certificate(username):
    return query_one(
        """
        SELECT *
        FROM device_certificates
        WHERE username = %s
        ORDER BY id DESC
        LIMIT 1
        """,
        (username,),
    )


def get_posture(username, device_ip):
    row = query_one(
        """
        SELECT *
        FROM device_posture
        WHERE username = %s
          AND device_ip = %s
        ORDER BY id DESC
        LIMIT 1
        """,
        (username, device_ip),
    )
    if row:
        return row

    return query_one(
        """
        SELECT *
        FROM device_posture
        WHERE username = %s
        ORDER BY id DESC
        LIMIT 1
        """,
        (username,),
    )


def get_policy(role, resource):
    return query_one(
        """
        SELECT *
        FROM enterprise_policies
        WHERE role = %s
          AND resource = %s
        ORDER BY id ASC
        LIMIT 1
        """,
        (role, resource),
    )


def get_session(session_id):
    return query_one(
        """
        SELECT *
        FROM access_sessions
        WHERE session_id = %s
        LIMIT 1
        """,
        (session_id,),
    )


def _policy_effect(policy):
    if not policy:
        return None

    for key in (
        "permission",
        "effect",
        "action",
        "decision",
        "policy_action",
        "access",
    ):
        if key in policy and policy.get(key) is not None:
            return str(policy.get(key)).strip().upper()

    return None

def _policy_min_trust(policy):
    for key in ("min_trust", "min_trust_score", "minimum_trust"):
        if key in policy and policy.get(key) is not None:
            try:
                return int(policy.get(key))
            except (TypeError, ValueError):
                pass
    return 0


def _policy_max_risk(policy):
    for key in ("max_risk", "max_risk_score", "maximum_risk"):
        if key in policy and policy.get(key) is not None:
            try:
                return int(policy.get(key))
            except (TypeError, ValueError):
                pass
    return 100


def calculate_trust(user, certificate, posture, device_ip, mfa_verified):
    trust = 0

    if user and str(user.get("account_status", "ACTIVE")).upper() == "ACTIVE":
        trust += 20

    if mfa_verified:
        trust += 25

    if certificate and str(certificate.get("status", "")).upper() == "ACTIVE":
        trust += 25

    expected_ip = user.get("device_ip") if user else None
    if expected_ip and str(expected_ip) == str(device_ip):
        trust += 15

    if posture and str(posture.get("posture_status", "")).upper() == "COMPLIANT":
        trust += 15

    return max(0, min(100, trust))


def _result(username, role, resource, decision, trust, risk, reason):
    save_decision(
        username=username,
        role=role,
        resource=resource,
        decision=decision,
        trust_score=trust,
        risk_score=risk,
        reason=reason,
    )
    return {
        "decision": decision,
        "username": username,
        "role": role,
        "resource": resource,
        "trust_score": trust,
        "risk_score": risk,
        "reason": reason,
    }


def evaluate_initial_access(
    username,
    device_ip,
    resource="portal",
    mfa_verified=False,
    certificate_verified=False,
):
    user = get_user(username)

    if not user:
        return _result(username, None, resource, "DENY", 0, 100, "Unknown user")

    role = user.get("role")
    account_status = str(user.get("account_status", "ACTIVE")).upper()

    if account_status != "ACTIVE":
        return _result(
            username, role, resource, "DENY", 0, 100,
            "Account is not active",
        )

    if not mfa_verified:
        return _result(
            username, role, resource, "DENY", 20, 80,
            "MFA has not been verified",
        )

    certificate = get_certificate(username)
    certificate_active = (
        certificate is not None
        and str(certificate.get("status", "")).upper() == "ACTIVE"
    )

    if not certificate_verified or not certificate_active:
        return _result(
            username, role, resource, "DENY", 30, 70,
            "Certificate is not active",
        )

    posture = get_posture(username, device_ip)
    trust = calculate_trust(
        user=user,
        certificate=certificate,
        posture=posture,
        device_ip=device_ip,
        mfa_verified=mfa_verified,
    )
    risk = get_current_identity_risk(username)

    policy = get_policy(role, resource)
    if not policy:
        return _result(
            username, role, resource, "DENY", trust, risk,
            "No enterprise policy found",
        )

    effect = _policy_effect(policy)
    if effect in ("DENY", "BLOCK"):
        return _result(
            username, role, resource, "DENY", trust, risk,
            "Role is not authorized for this resource",
        )

    min_trust = _policy_min_trust(policy)
    max_risk = _policy_max_risk(policy)

    if trust < min_trust:
        return _result(
            username, role, resource, "DENY", trust, risk,
            f"Trust {trust} is below required {min_trust}",
        )

    if risk > max_risk:
        return _result(
            username, role, resource, "DENY", trust, risk,
            f"Risk {risk} exceeds allowed {max_risk}",
        )

    return _result(
        username, role, resource, "GRANT", trust, risk,
        "Enterprise policy requirements satisfied",
    )


def evaluate_session_access(session_id, resource):
    session = get_session(session_id)

    if not session:
        return {
            "decision": "DENY",
            "username": None,
            "role": None,
            "resource": resource,
            "trust_score": 0,
            "risk_score": 100,
            "reason": "Session does not exist",
        }

    username = session.get("username")

    if str(session.get("status", "")).upper() != "ACTIVE":
        user = get_user(username)
        return {
            "decision": "DENY",
            "username": username,
            "role": user.get("role") if user else None,
            "resource": resource,
            "trust_score": 0,
            "risk_score": 100,
            "reason": "Session is not active",
        }

    user = get_user(username)
    if not user:
        return {
            "decision": "REVOKE",
            "username": username,
            "role": None,
            "resource": resource,
            "trust_score": 0,
            "risk_score": 100,
            "reason": "User no longer exists",
        }

    role = user.get("role")

    if str(user.get("account_status", "ACTIVE")).upper() != "ACTIVE":
        return _result(
            username, role, resource, "REVOKE", 0, 100,
            "Account is not active",
        )

    certificate = get_certificate(username)
    if not certificate or str(certificate.get("status", "")).upper() != "ACTIVE":
        return _result(
            username, role, resource, "REVOKE", 30, 70,
            "Certificate is not active",
        )

    mfa_verified = bool(session.get("mfa_verified", 0))
    certificate_verified = bool(session.get("certificate_verified", 0))

    if not mfa_verified or not certificate_verified:
        return _result(
            username, role, resource, "REVOKE", 20, 80,
            "Session authentication assurance is insufficient",
        )

    device_ip = session.get("device_ip")
    posture = get_posture(username, device_ip)
    trust = calculate_trust(
        user=user,
        certificate=certificate,
        posture=posture,
        device_ip=device_ip,
        mfa_verified=mfa_verified,
    )
    risk = get_current_identity_risk(username)

    policy = get_policy(role, resource)
    if not policy:
        return _result(
            username, role, resource, "DENY", trust, risk,
            "No enterprise policy found",
        )

    effect = _policy_effect(policy)
    if effect in ("DENY", "BLOCK"):
        return _result(
            username, role, resource, "DENY", trust, risk,
            "Role is not authorized for this resource",
        )

    min_trust = _policy_min_trust(policy)
    max_risk = _policy_max_risk(policy)

    if trust < min_trust:
        return _result(
            username, role, resource, "REVOKE", trust, risk,
            f"Current trust {trust} is below required {min_trust}",
        )

    if risk > max_risk:
        return _result(
            username, role, resource, "REVOKE", trust, risk,
            f"Current dynamic risk {risk} exceeds allowed {max_risk}",
        )

    return _result(
        username, role, resource, "GRANT", trust, risk,
        "Enterprise policy requirements satisfied",
    )
