from datetime import datetime
from database import get_connection

MAX_RISK = 100
DECAY_INTERVAL_MINUTES = 5
DECAY_POINTS = 10


def clamp(value, minimum=0, maximum=100):
    try:
        value = int(value)
    except (TypeError, ValueError):
        value = 0
    return max(minimum, min(maximum, value))


def _close(cursor, connection):
    try:
        if cursor is not None:
            cursor.close()
    finally:
        if connection is not None:
            connection.close()


def get_identity_risk(username):
    connection = None
    cursor = None
    try:
        connection = get_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT *
            FROM identity_risk
            WHERE username = %s
            LIMIT 1
            """,
            (username,),
        )
        row = cursor.fetchone()

        if row:
            return row

        cursor.close()
        cursor = connection.cursor()
        cursor.execute(
            """
            INSERT INTO identity_risk
                (username, failed_login_risk, behavior_risk,
                 total_risk, reason)
            VALUES (%s, 0, 0, 0, 'Normal')
            """,
            (username,),
        )
        connection.commit()
        return {
            "username": username,
            "failed_login_risk": 0,
            "behavior_risk": 0,
            "total_risk": 0,
            "reason": "Normal",
            "updated_at": datetime.now(),
        }
    finally:
        _close(cursor, connection)


def recalculate_identity_risk(username):
    row = get_identity_risk(username)
    failed = clamp(row.get("failed_login_risk", 0))
    behavior = clamp(row.get("behavior_risk", 0))
    total = clamp(failed + behavior)

    connection = None
    cursor = None
    try:
        connection = get_connection()
        cursor = connection.cursor()
        cursor.execute(
            """
            UPDATE identity_risk
            SET total_risk = %s
            WHERE username = %s
            """,
            (total, username),
        )
        connection.commit()
        return total
    finally:
        _close(cursor, connection)


def set_failed_login_risk(username, failed_attempts):
    if failed_attempts <= 0:
        risk = 0
        reason = "No recent failed authentication"
    elif failed_attempts == 1:
        risk = 10
        reason = "One recent failed authentication"
    elif failed_attempts == 2:
        risk = 25
        reason = "Multiple recent failed authentications"
    else:
        risk = 40
        reason = "Repeated failed authentication"

    connection = None
    cursor = None
    try:
        connection = get_connection()
        cursor = connection.cursor()
        cursor.execute(
            """
            INSERT INTO identity_risk
                (username, failed_login_risk, behavior_risk,
                 total_risk, reason)
            VALUES (%s, %s, 0, %s, %s)
            ON DUPLICATE KEY UPDATE
                failed_login_risk = VALUES(failed_login_risk),
                reason = VALUES(reason),
                updated_at = CURRENT_TIMESTAMP
            """,
            (username, risk, risk, reason),
        )
        connection.commit()
    finally:
        _close(cursor, connection)

    return recalculate_identity_risk(username)


def clear_failed_login_risk(username):
    connection = None
    cursor = None
    try:
        connection = get_connection()
        cursor = connection.cursor()
        cursor.execute(
            """
            INSERT INTO identity_risk
                (username, failed_login_risk, behavior_risk,
                 total_risk, reason)
            VALUES (%s, 0, 0, 0, 'Successful authentication')
            ON DUPLICATE KEY UPDATE
                failed_login_risk = 0,
                reason = 'Successful authentication',
                updated_at = CURRENT_TIMESTAMP
            """,
            (username,),
        )
        connection.commit()
    finally:
        _close(cursor, connection)

    return recalculate_identity_risk(username)


def add_identity_behavior_risk(username, amount, reason):
    row = get_identity_risk(username)
    current = clamp(row.get("behavior_risk", 0))
    new_value = clamp(current + amount)

    connection = None
    cursor = None
    try:
        connection = get_connection()
        cursor = connection.cursor()
        cursor.execute(
            """
            UPDATE identity_risk
            SET behavior_risk = %s,
                reason = %s,
                updated_at = CURRENT_TIMESTAMP
            WHERE username = %s
            """,
            (new_value, reason, username),
        )
        connection.commit()
    finally:
        _close(cursor, connection)

    return recalculate_identity_risk(username)


def clear_behavior_risk(username, reason="Security condition resolved"):
    connection = None
    cursor = None
    try:
        connection = get_connection()
        cursor = connection.cursor()
        cursor.execute(
            """
            INSERT INTO identity_risk
                (username, failed_login_risk, behavior_risk,
                 total_risk, reason)
            VALUES (%s, 0, 0, 0, %s)
            ON DUPLICATE KEY UPDATE
                behavior_risk = 0,
                reason = VALUES(reason),
                updated_at = CURRENT_TIMESTAMP
            """,
            (username, reason),
        )
        connection.commit()
    finally:
        _close(cursor, connection)

    return recalculate_identity_risk(username)


def apply_risk_decay(username):
    row = get_identity_risk(username)
    updated_at = row.get("updated_at")

    if not updated_at:
        return clamp(row.get("total_risk", 0))

    if isinstance(updated_at, str):
        try:
            updated_at = datetime.fromisoformat(updated_at)
        except ValueError:
            return clamp(row.get("total_risk", 0))

    elapsed_seconds = max(0, (datetime.now() - updated_at).total_seconds())
    interval_seconds = DECAY_INTERVAL_MINUTES * 60
    intervals = int(elapsed_seconds // interval_seconds)

    if intervals <= 0:
        return clamp(row.get("total_risk", 0))

    current_behavior = clamp(row.get("behavior_risk", 0))
    recovered = intervals * DECAY_POINTS
    new_behavior = clamp(current_behavior - recovered)

    if new_behavior == current_behavior:
        return clamp(row.get("total_risk", 0))

    connection = None
    cursor = None
    try:
        connection = get_connection()
        cursor = connection.cursor()
        cursor.execute(
            """
            UPDATE identity_risk
            SET behavior_risk = %s,
                reason = 'Behavior risk decayed after stable period',
                updated_at = CURRENT_TIMESTAMP
            WHERE username = %s
            """,
            (new_behavior, username),
        )
        connection.commit()
    finally:
        _close(cursor, connection)

    return recalculate_identity_risk(username)


def get_current_identity_risk(username):
    apply_risk_decay(username)
    row = get_identity_risk(username)
    return clamp(row.get("total_risk", 0))


def record_network_risk(source_ip, risk_score, attack_type, threat_level):
    risk_score = clamp(risk_score)

    connection = None
    cursor = None
    try:
        connection = get_connection()
        cursor = connection.cursor()
        cursor.execute(
            """
            INSERT INTO network_risk
                (source_ip, risk_score, threat_level, last_attack_type)
            VALUES (%s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                risk_score = GREATEST(risk_score, VALUES(risk_score)),
                threat_level = VALUES(threat_level),
                last_attack_type = VALUES(last_attack_type),
                updated_at = CURRENT_TIMESTAMP
            """,
            (source_ip, risk_score, threat_level, attack_type),
        )
        connection.commit()
    finally:
        _close(cursor, connection)


def get_network_risk(source_ip):
    connection = None
    cursor = None
    try:
        connection = get_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT *
            FROM network_risk
            WHERE source_ip = %s
            LIMIT 1
            """,
            (source_ip,),
        )
        return cursor.fetchone()
    finally:
        _close(cursor, connection)
