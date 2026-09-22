import secrets
from database import get_connection


def _close(cursor, connection):
    try:
        if cursor is not None:
            cursor.close()
    finally:
        if connection is not None:
            connection.close()


def create_session(
    username,
    device_ip,
    mfa_verified=True,
    certificate_verified=True,
):
    """
    PA action for a PE GRANT decision.
    For a simple demo, keep one ACTIVE session per user.
    """
    connection = None
    cursor = None
    try:
        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            UPDATE access_sessions
            SET status = 'REVOKED',
                revoked_at = NOW()
            WHERE username = %s
              AND status = 'ACTIVE'
            """,
            (username,),
        )

        session_id = secrets.token_urlsafe(32)

        cursor.execute(
            """
            INSERT INTO access_sessions
                (session_id, username, device_ip, status,
                 mfa_verified, certificate_verified, auth_level,
                 created_at, last_seen)
            VALUES
                (%s, %s, %s, 'ACTIVE', %s, %s, 'MFA_CERT', NOW(), NOW())
            """,
            (
                session_id,
                username,
                device_ip,
                int(bool(mfa_verified)),
                int(bool(certificate_verified)),
            ),
        )
        connection.commit()
        return session_id
    except Exception as error:
        if connection is not None:
            connection.rollback()
        print("[PA CREATE SESSION ERROR]", error)
        return None
    finally:
        _close(cursor, connection)


def revoke_session(session_id, reason=None):
    """PA action for a PE REVOKE decision or manual Admin action."""
    connection = None
    cursor = None
    try:
        connection = get_connection()
        cursor = connection.cursor()
        cursor.execute(
            """
            UPDATE access_sessions
            SET status = 'REVOKED',
                revoked_at = NOW()
            WHERE session_id = %s
              AND status = 'ACTIVE'
            """,
            (session_id,),
        )
        changed = cursor.rowcount
        connection.commit()
        return changed > 0
    except Exception as error:
        if connection is not None:
            connection.rollback()
        print("[PA REVOKE SESSION ERROR]", error, reason or "")
        return False
    finally:
        _close(cursor, connection)


def revoke_user_sessions(username, reason=None):
    connection = None
    cursor = None
    try:
        connection = get_connection()
        cursor = connection.cursor()
        cursor.execute(
            """
            UPDATE access_sessions
            SET status = 'REVOKED',
                revoked_at = NOW()
            WHERE username = %s
              AND status = 'ACTIVE'
            """,
            (username,),
        )
        changed = cursor.rowcount
        connection.commit()
        return changed
    except Exception as error:
        if connection is not None:
            connection.rollback()
        print("[PA REVOKE USER SESSIONS ERROR]", error, reason or "")
        return 0
    finally:
        _close(cursor, connection)
