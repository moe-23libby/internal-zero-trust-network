from database import get_connection


def log_timeline(
    event_type,
    username=None,
    source_ip=None,
    description="",
    severity="Info"
):
    db = None
    cursor = None

    try:
        db = get_connection()
        cursor = db.cursor()

        cursor.execute(
            """
            INSERT INTO incident_timeline
            (
                event_type,
                username,
                source_ip,
                description,
                severity
            )
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                event_type,
                username,
                source_ip,
                description,
                severity
            )
        )

        db.commit()

    except Exception as error:
        print(
            "[TIMELINE ERROR]",
            error
        )

    finally:
        if cursor is not None:
            cursor.close()

        if db is not None:
            db.close()
