
import os
import secrets
import hashlib
import base64
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import psycopg2
from psycopg2.extras import Json
from flask import Flask, redirect, request, jsonify
import requests
from cryptography.fernet import Fernet, InvalidToken

app = Flask(__name__)

OURA_AUTHORIZE_URL = "https://cloud.ouraring.com/oauth/authorize"
OURA_TOKEN_URL = "https://api.ouraring.com/oauth/token"

OURA_SCOPES = [
    "email",
    "personal",
    "daily",
    "heartrate",
    "workout",
    "tag",
    "session",
    "spo2",
]

def get_env(name):
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Missing environment variable: {name}")
    return value

def get_db():
    return psycopg2.connect(get_env("DATABASE_URL"))

def cipher():
    secret = get_env("TOKEN_ENCRYPTION_SECRET")
    key = base64.urlsafe_b64encode(
        hashlib.sha256(secret.encode("utf-8")).digest()
    )
    return Fernet(key)

def encrypt(value):
    return cipher().encrypt(value.encode()).decode()

def decrypt(value):
    return cipher().decrypt(value.encode()).decode()
def get_valid_access_token():
    """
    获取有效的 Oura Access Token。
    如果即将过期，则自动使用 Refresh Token 续期。
    Oura 的 Refresh Token 是一次性令牌，
    所以每次续期必须同时保存新的两个令牌。
    """

    now = datetime.now(timezone.utc)

    with get_db() as conn:
        with conn.cursor() as cur:

            # 锁定令牌记录，避免并发续期
            cur.execute("""
                SELECT access_token, refresh_token, expires_at
                FROM oauth_tokens
                WHERE id = 1
                FOR UPDATE
            """)

            row = cur.fetchone()

            if not row:
                raise RuntimeError("Oura account is not connected.")

            access_token = decrypt(row[0])
            refresh_token = decrypt(row[1])
            expires_at = row[2]

            # 如果距离过期还有5分钟以上，直接使用旧令牌
            if expires_at and expires_at > now + timedelta(minutes=5):
                return access_token

            # 使用 Refresh Token 请求新令牌
            response = requests.post(
                OURA_TOKEN_URL,
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": get_env("OURA_CLIENT_ID"),
                    "client_secret": get_env("OURA_CLIENT_SECRET"),
                },
                headers={
                    "User-Agent": "OuraPersonalSleepTracker/1.0"
                },
                timeout=30,
            )

            if not response.ok:
                app.logger.error(
                    "Oura token refresh failed: HTTP %s",
                    response.status_code
                )
                raise RuntimeError("Oura token refresh failed.")

            tokens = response.json()

            new_access_token = tokens.get("access_token")
            new_refresh_token = tokens.get("refresh_token")

            if not new_access_token or not new_refresh_token:
                raise RuntimeError("Oura did not return new tokens.")

            new_expires_at = now + timedelta(
                seconds=int(tokens.get("expires_in", 86400))
            )

            # 同时更新两个令牌
            cur.execute("""
                UPDATE oauth_tokens
                SET access_token = %s,
                    refresh_token = %s,
                    expires_at = %s,
                    updated_at = NOW()
                WHERE id = 1
            """, (
                encrypt(new_access_token),
                encrypt(new_refresh_token),
                new_expires_at,
            ))

            return new_access_token
def fetch_oura_collection(endpoint, start_date, end_date, token):
    """获取 Oura 数据并自动处理分页。"""

    url = f"https://api.ouraring.com/v2/usercollection/{endpoint}"

    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": "OuraPersonalSleepTracker/1.0",
    }

    all_records = []
    next_token = None

    for page in range(100):
        params = {
            "start_date": start_date,
            "end_date": end_date,
        }

        if next_token:
            params["next_token"] = next_token

        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=30,
        )

        if not response.ok:
            app.logger.error(
                "Oura data request failed: endpoint=%s HTTP=%s",
                endpoint,
                response.status_code,
            )
            raise RuntimeError(
                f"Oura API request failed: {endpoint}"
            )

        result = response.json()
        records = result.get("data", [])

        all_records.extend(records)

        next_token = result.get("next_token")

        if not next_token:
            break
    else:
        raise RuntimeError("Oura pagination limit reached.")

    return all_records
def fetch_oura_heartrate(start_datetime, end_datetime, token):
    """获取 Oura 全天心率数据，并处理分页。"""

    url = "https://api.ouraring.com/v2/usercollection/heartrate"

    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": "OuraPersonalSleepTracker/1.0",
    }

    all_records = []
    next_token = None

    for page in range(100):
        params = {
            "start_datetime": start_datetime,
            "end_datetime": end_datetime,
        }

        if next_token:
            params["next_token"] = next_token

        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=60,
        )

        if not response.ok:
            app.logger.error(
                "Oura heartrate request failed: HTTP %s",
                response.status_code,
            )
            raise RuntimeError("Oura heartrate request failed.")

        result = response.json()
        all_records.extend(result.get("data", []))

        next_token = result.get("next_token")
        if not next_token:
            break
    else:
        raise RuntimeError("Heartrate pagination limit reached.")

    return all_records


def sync_heartrate_data():
    """同步最近30天的全天心率数据。"""

    end_datetime = datetime.now(timezone.utc)
    start_datetime = end_datetime - timedelta(days=29)

    token = get_valid_access_token()

    records = fetch_oura_heartrate(
        start_datetime.isoformat(),
        end_datetime.isoformat(),
        token,
    )

    count = save_oura_records("heartrate", records)

    return {
        "record_count": count,
        "status": "success",
        "period_start": start_datetime.isoformat(),
        "period_end": end_datetime.isoformat(),
    }

def save_oura_records(data_type, records):
    """将 Oura 数据保存到 PostgreSQL，按 ID 或时间戳去重。"""

    saved_count = 0

    with get_db() as conn:
        with conn.cursor() as cur:
            for record in records:
                document_id = (
                    record.get("id")
                    or record.get("timestamp")
                )

                if not document_id:
                    continue

                record_day = (
                    record.get("day")
                    or record.get("start_day")
                    or (
                        record.get("timestamp", "")[:10]
                        if record.get("timestamp")
                        else None
                    )
                )

                cur.execute("""
                    INSERT INTO oura_data (
                        data_type,
                        document_id,
                        data,
                        day,
                        synced_at
                    )
                    VALUES (%s, %s, %s, %s, NOW())
                    ON CONFLICT (data_type, document_id)
                    DO UPDATE SET
                        data = EXCLUDED.data,
                        day = EXCLUDED.day,
                        synced_at = NOW()
                """, (
                    data_type,
                    document_id,
                    Json(record),
                    record_day,
                ))

                saved_count += 1

    return saved_count


def sync_sleep_data():
    """同步最近30天的睡眠记录和每日睡眠评分。"""

    end_date = datetime.now(timezone.utc).date()
    start_date = end_date - timedelta(days=29)

    start = start_date.isoformat()
    end = end_date.isoformat()

    token = get_valid_access_token()

    sleep_records = fetch_oura_collection(
        "sleep", start, end, token
    )

    daily_records = fetch_oura_collection(
        "daily_sleep", start, end, token
    )

    sleep_count = save_oura_records(
        "sleep", sleep_records
    )

    daily_count = save_oura_records(
        "daily_sleep", daily_records
    )

    return {
        "period_start": start,
        "period_end": end,
        "sleep_records": sleep_count,
        "daily_sleep_records": daily_count,
    }
def init_db():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS oauth_states (
                    state_hash TEXT PRIMARY KEY,
                    verifier TEXT NOT NULL,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS oauth_tokens (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    access_token TEXT NOT NULL,
                    refresh_token TEXT NOT NULL,
                    expires_at TIMESTAMPTZ,
                    scopes TEXT,
                    updated_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS oura_data (
                    id BIGSERIAL PRIMARY KEY,
                    data_type TEXT NOT NULL,
                    document_id TEXT NOT NULL,
                    data JSONB NOT NULL,
                    day DATE,
                    synced_at TIMESTAMPTZ DEFAULT NOW(),
                    UNIQUE (data_type, document_id)
                )
            """)
def sync_additional_data():
    """同步最近30天的活动、运动和血氧数据。"""

    end_date = datetime.now(timezone.utc).date()
    start_date = end_date - timedelta(days=29)

    start = start_date.isoformat()
    end = end_date.isoformat()

    token = get_valid_access_token()

    endpoints = [
        "daily_activity",
        "workout",
        "daily_spo2",
        "daily_readiness",
        "daily_stress",
    ]
    results = {}

    for endpoint in endpoints:
        try:
            records = fetch_oura_collection(
                endpoint, start, end, token
            )

            count = save_oura_records(endpoint, records)

            results[endpoint] = {
                "record_count": count,
                "status": "success",
            }

        except Exception:
            app.logger.exception(
                "Failed to sync Oura endpoint: %s",
                endpoint
            )

            results[endpoint] = {
                "status": "error",
                "message": "This data type could not be synchronized."
            }

    return results

def sync_context_data():
    """Synchronize enhanced tags and sessions."""

    end_date = datetime.now(timezone.utc).date()
    start_date = end_date - timedelta(days=29)

    start = start_date.isoformat()
    end = end_date.isoformat()

    token = get_valid_access_token()
    results = {}

    for endpoint in ["enhanced_tag", "session"]:
        try:
            records = fetch_oura_collection(
                endpoint, start, end, token
            )
            count = save_oura_records(endpoint, records)

            results[endpoint] = {
                "record_count": count,
                "status": "success"
            }

        except Exception:
            app.logger.exception(
                "Failed to sync %s", endpoint
            )
            results[endpoint] = {
                "status": "error",
                "message": "Synchronization failed."
            }

    return results

@app.route("/")
def home():
    return "Oura Personal Sleep Tracker is running."

@app.route("/health")
def health():
    try:
        init_db()
        return jsonify({"status": "ok", "database": "connected"})
    except Exception:
        return jsonify({
            "status": "error",
            "database": "unavailable"
        }), 503

@app.route("/login")
def login():
    try:
        client_id = get_env("OURA_CLIENT_ID")
        redirect_uri = get_env("OURA_REDIRECT_URI")

        state = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(64)

        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()
        ).decode().rstrip("=")

        state_hash = hashlib.sha256(state.encode()).hexdigest()

        init_db()

        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    DELETE FROM oauth_states
                    WHERE created_at < NOW() - INTERVAL '10 minutes'
                """)
                cur.execute("""
                    INSERT INTO oauth_states (state_hash, verifier)
                    VALUES (%s, %s)
                """, (state_hash, encrypt(verifier)))

        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(OURA_SCOPES),
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }

        return redirect(
            OURA_AUTHORIZE_URL + "?" + urlencode(params)
        )

    except Exception:
        app.logger.exception("OAuth login initialization failed")
        return "Unable to start Oura authorization. Check server configuration.", 500

@app.route("/oauth/callback")
def oauth_callback():
    error = request.args.get("error")

    if error:
        return "Oura authorization was declined or failed.", 400

    code = request.args.get("code")
    state = request.args.get("state")

    if not code or not state:
        return "Missing authorization code or state.", 400

    try:
        init_db()

        state_hash = hashlib.sha256(state.encode()).hexdigest()

        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    DELETE FROM oauth_states
                    WHERE state_hash = %s
                    AND created_at > NOW() - INTERVAL '10 minutes'
                    RETURNING verifier
                """, (state_hash,))
                row = cur.fetchone()

        if not row:
            return "Invalid or expired authorization state.", 400

        verifier = decrypt(row[0])

        token_response = requests.post(
            OURA_TOKEN_URL,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": get_env("OURA_REDIRECT_URI"),
                "client_id": get_env("OURA_CLIENT_ID"),
                "client_secret": get_env("OURA_CLIENT_SECRET"),
                "code_verifier": verifier,
            },
            headers={"User-Agent": "OuraPersonalSleepTracker/1.0"},
            timeout=30,
        )

        if not token_response.ok:
            app.logger.error(
                "Oura token exchange failed: HTTP %s",
                token_response.status_code
            )
            return "Oura token exchange failed. Please check server logs.", 502

        tokens = token_response.json()

        access_token = tokens.get("access_token")
        refresh_token = tokens.get("refresh_token")

        if not access_token or not refresh_token:
            return "Oura did not return the expected tokens.", 502

        expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=int(tokens.get("expires_in", 86400))
        )

        granted_scopes = tokens.get(
            "scope", " ".join(OURA_SCOPES)
        )

        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO oauth_tokens (
                        id, access_token, refresh_token,
                        expires_at, scopes, updated_at
                    )
                    VALUES (1, %s, %s, %s, %s, NOW())
                    ON CONFLICT (id) DO UPDATE SET
                        access_token = EXCLUDED.access_token,
                        refresh_token = EXCLUDED.refresh_token,
                        expires_at = EXCLUDED.expires_at,
                        scopes = EXCLUDED.scopes,
                        updated_at = NOW()
                """, (
                    encrypt(access_token),
                    encrypt(refresh_token),
                    expires_at,
                    granted_scopes,
                ))

        return """
        <h2>Oura authorization successful</h2>
        <p>Your authorization tokens have been securely stored.</p>
        <p>You may close this page.</p>
        """

    except Exception:
        app.logger.exception("OAuth callback failed")
        return "Authorization processing failed. Check server logs.", 500
@app.route("/sync", methods=["GET", "POST"])
def sync_page():

    if request.method == "GET":
        return """
        <html>
        <head>
            <meta name="viewport"
                  content="width=device-width, initial-scale=1">
            <title>Oura Data Sync</title>
        </head>
        <body style="font-family:Arial;padding:30px;">
            <h2>Oura Sleep Data Sync</h2>
            <form method="POST">
                <p>Enter your sync password:</p>
                <input
                    type="password"
                    name="secret"
                    required
                    style="padding:12px;width:90%;"
                >
                <br><br>
                <button
                    type="submit"
                    style="padding:12px 24px;"
                >
                    Start Sync
                </button>
            </form>
        </body>
        </html>
        """

    supplied_secret = request.form.get("secret", "")

    if not secrets.compare_digest(
        supplied_secret,
        get_env("OURA_SYNC_SECRET")
    ):
        return "Invalid password.", 403


    try:
        result = sync_sleep_data()
        additional_result = sync_additional_data()
        context_result = {"status": "temporarily_disabled"}
        heartrate_result = {"status": "temporarily_disabled"}

        return jsonify({
            "status": "success",
            "sleep": result,
            "additional_data": additional_result,
            "context_data": context_result,
            "heartrate": heartrate_result,
        })

    except Exception:
        app.logger.exception("Sleep data synchronization failed")
        return jsonify({
            "status": "error",
            "message": "Synchronization failed. Check server logs."
        }), 500
@app.route("/stats", methods=["GET", "POST"])
def stats_page():

    if request.method == "GET":
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <meta name="viewport"
                  content="width=device-width, initial-scale=1">
            <title>Oura Database Statistics</title>
        </head>
        <body style="font-family:Arial;padding:30px;">
            <h2>Oura Database Statistics</h2>
            <form method="POST">
                <p>Enter your sync password:</p>
                <input
                    type="password"
                    name="secret"
                    required
                    style="padding:12px;width:90%;"
                >
                <br><br>
                <button type="submit" style="padding:12px 24px;">
                    View Statistics
                </button>
            </form>
        </body>
        </html>
        """

    supplied_secret = request.form.get("secret", "")

    if not secrets.compare_digest(
        supplied_secret,
        get_env("OURA_SYNC_SECRET")
    ):
        return "Invalid password.", 403

    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT
                        data_type,
                        COUNT(*),
                        MIN(day),
                        MAX(day),
                        MAX(synced_at)
                    FROM oura_data
                    GROUP BY data_type
                    ORDER BY data_type
                """)

                rows = cur.fetchall()

        statistics = []

        for row in rows:
            statistics.append({
                "data_type": row[0],
                "record_count": row[1],
                "first_day": (
                    row[2].isoformat() if row[2] else None
                ),
                "last_day": (
                    row[3].isoformat() if row[3] else None
                ),
                "last_synced_at": (
                    row[4].isoformat() if row[4] else None
                ),
            })

        return jsonify({
            "status": "success",
            "statistics": statistics
        })

    except Exception:
        app.logger.exception("Database statistics failed")
        return jsonify({
            "status": "error",
            "message": "Unable to read database statistics."
        }), 500
@app.route("/api/status")
def api_status():
    try:
        init_db()

        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT expires_at, scopes
                    FROM oauth_tokens
                    WHERE id = 1
                """)
                row = cur.fetchone()

        if not row:
            return jsonify({"connected": False})

        return jsonify({
            "connected": True,
            "expires_at": row[0].isoformat() if row[0] else None,
            "scopes": row[1],
        })

    except Exception:
        app.logger.exception("Status check failed")
        return jsonify({"error": "Status unavailable"}), 500
@app.route("/api/data", methods=["GET"])
def api_get_data():
    api_key = os.getenv("OURA_API_KEY")

    if not api_key:
        return jsonify({"error": "API not configured"}), 503

    auth_header = request.headers.get("Authorization", "")
    supplied_key = (
        auth_header[7:]
        if auth_header.startswith("Bearer ")
        else ""
    )

    if not secrets.compare_digest(supplied_key, api_key):
        return jsonify({"error": "Unauthorized"}), 401

    allowed_types = {
        "sleep",
        "daily_sleep",
        "daily_activity",
        "daily_spo2",
        "daily_readiness",
        "daily_stress",
        "heartrate",
        "workout",
        "enhanced_tag",
        "session"
    }
    data_type = request.args.get("data_type", "all")

    if data_type != "all" and data_type not in allowed_types:
        return jsonify({"error": "Unsupported data_type"}), 400

    try:
        end = (
            datetime.fromisoformat(request.args["end_date"]).date()
            if request.args.get("end_date")
            else datetime.now(timezone.utc).date()
        )

        start = (
            datetime.fromisoformat(request.args["start_date"]).date()
            if request.args.get("start_date")
            else end - timedelta(days=29)
        )

        limit = int(request.args.get("limit", 200))

    except (ValueError, TypeError):
        return jsonify({"error": "Invalid date or limit"}), 400

    if start > end or limit < 1:
        return jsonify({"error": "Invalid query range or limit"}), 400

    limit = min(limit, 500)

    try:
        with get_db() as conn:
            with conn.cursor() as cur:

                if data_type == "all":
                    cur.execute("""
                        SELECT data_type, document_id, data, day
                        FROM oura_data
                        WHERE day >= %s AND day <= %s
                        ORDER BY day DESC NULLS LAST
                        LIMIT %s
                    """, (start, end, limit))

                else:
                    cur.execute("""
                        SELECT data_type, document_id, data, day
                        FROM oura_data
                        WHERE data_type = %s
                          AND day >= %s AND day <= %s
                        ORDER BY day DESC NULLS LAST
                        LIMIT %s
                    """, (data_type, start, end, limit))

                rows = cur.fetchall()

        records = [
            {
                "data_type": row[0],
                "document_id": row[1],
                "data": row[2],
                "day": row[3].isoformat() if row[3] else None
            }
            for row in rows
        ]

        return jsonify({
            "status": "success",
            "count": len(records),
            "start_date": start.isoformat(),
            "end_date": end.isoformat(),
            "records": records
        })

    except Exception:
        app.logger.exception("Oura data query failed")
        return jsonify({"error": "Data query failed"}), 500
