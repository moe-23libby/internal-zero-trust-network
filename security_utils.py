from database import get_connection


MAX_FAILED_ATTEMPTS = 3
LOCK_MINUTES = 15


def log_access(
    username=None,
    role=None,
    device_ip=None,
    resource="Unknown",
    action="ACCESS",
    result="DENY",
    reason=""
):
    db = None
    cursor = None

    try:
        db = get_connection()
        cursor = db.cursor()

        cursor.execute(
            """
            INSERT INTO access_history
            (
                username,
                role,
                device_ip,
                resource,
                action,
                result,
                reason
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                username,
                role,
                device_ip,
                resource,
                action,
                result,
                reason
            )
        )

        db.commit()

    except Exception as error:
        print("[ACCESS HISTORY ERROR]", error)

    finally:
        if cursor is not None:
            cursor.close()

        if db is not None:
            db.close()


def create_security_alert(
    username=None,
    source_ip=None,
    alert_type="Security Event",
    severity="Medium",
    description=""
):
    db = None
    cursor = None

    try:
        db = get_connection()
        cursor = db.cursor()

        cursor.execute(
            """
            INSERT INTO security_alerts
            (
                username,
                source_ip,
                alert_type,
                severity,
                description,
                status
            )
            VALUES (%s, %s, %s, %s, %s, 'OPEN')
            """,
            (
                username,
                source_ip,
                alert_type,
                severity,
                description
            )
        )

        db.commit()

    except Exception as error:
        print("[SECURITY ALERT ERROR]", error)

    finally:
        if cursor is not None:
            cursor.close()

        if db is not None:
            db.close()


def get_account_lock_state(username):
    db = None
    cursor = None

    try:
        db = get_connection()
        cursor = db.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT
                username,
                failed_attempts,
                account_status,
                locked_until
            FROM users
            WHERE username = %s
            LIMIT 1
            """,
            (username,)
        )

        user = cursor.fetchone()

        if user is None:
            return None

        # Automatic unlock after timeout
        if (
            user["account_status"] == "LOCKED"
            and user["locked_until"] is not None
        ):
            cursor.execute(
                """
                SELECT NOW() >= %s AS lock_expired
                """,
                (user["locked_until"],)
            )

            result = cursor.fetchone()

            if result and result["lock_expired"]:
                cursor.execute(
                    """
                    UPDATE users
                    SET
                        failed_attempts = 0,
                        account_status = 'ACTIVE',
                        locked_until = NULL
                    WHERE username = %s
                    """,
                    (username,)
                )

                db.commit()

                user["failed_attempts"] = 0
                user["account_status"] = "ACTIVE"
                user["locked_until"] = None

        return user

    except Exception as error:
        print("[LOCK STATE ERROR]", error)
        return None

    finally:
        if cursor is not None:
            cursor.close()

        if db is not None:
            db.close()


def register_failed_attempt(
    username,
    source_ip,
    reason
):
    db = None
    cursor = None

    try:
        db = get_connection()
        cursor = db.cursor(dictionary=True)

        cursor.execute(
            """
            UPDATE users
            SET failed_attempts = failed_attempts + 1
            WHERE username = %s
            """,
            (username,)
        )

        cursor.execute(
            """
            SELECT
                failed_attempts,
                account_status
            FROM users
            WHERE username = %s
            LIMIT 1
            """,
            (username,)
        )

        state = cursor.fetchone()

        if state is None:
            db.commit()
            return 0, False

        attempts = state["failed_attempts"]
        locked = False

        if attempts >= MAX_FAILED_ATTEMPTS:
            locked = True

            cursor.execute(
                """
                UPDATE users
                SET
                    account_status = 'LOCKED',
                    locked_until =
                        DATE_ADD(
                            NOW(),
                            INTERVAL 15 MINUTE
                        )
                WHERE username = %s
                """,
                (username,)
            )

            cursor.execute(
                """
                INSERT INTO security_alerts
                (
                    username,
                    source_ip,
                    alert_type,
                    severity,
                    description,
                    status
                )
                VALUES
                (
                    %s,
                    %s,
                    'MULTIPLE_FAILED_LOGINS',
                    'High',
                    %s,
                    'OPEN'
                )
                """,
                (
                    username,
                    source_ip,
                    (
                        f"Account locked after "
                        f"{attempts} failed login attempts"
                    )
                )
            )

        db.commit()

        return attempts, locked

    except Exception as error:
        print("[FAILED LOGIN ERROR]", error)
        return 0, False

    finally:
        if cursor is not None:
            cursor.close()

        if db is not None:
            db.close()


def clear_failed_attempts(username):
    db = None
    cursor = None

    try:
        db = get_connection()
        cursor = db.cursor()

        cursor.execute(
            """
            UPDATE users
            SET
                failed_attempts = 0,
                account_status = 'ACTIVE',
                locked_until = NULL
            WHERE username = %s
            """,
            (username,)
        )

        db.commit()

    except Exception as error:
        print("[RESET FAILED LOGIN ERROR]", error)

    finally:
        if cursor is not None:
            cursor.close()

        if db is not None:
            db.close()


def admin_unlock_user(
    username,
    admin_username="admin"
):
    db = None
    cursor = None

    try:
        db = get_connection()
        cursor = db.cursor()

        cursor.execute(
            """
            UPDATE users
            SET
                failed_attempts = 0,
                account_status = 'ACTIVE',
                locked_until = NULL
            WHERE username = %s
            """,
            (username,)
        )

        cursor.execute(
            """
            UPDATE security_alerts
            SET
                status = 'RESOLVED',
                resolved_at = NOW(),
                resolved_by = %s
            WHERE username = %s
              AND alert_type = 'MULTIPLE_FAILED_LOGINS'
              AND status = 'OPEN'
            """,
            (
                admin_username,
                username
            )
        )

        db.commit()

        return True

    except Exception as error:
        print("[ADMIN UNLOCK ERROR]", error)
        return False

    finally:
        if cursor is not None:
            cursor.close()

        if db is not None:
            db.close()
