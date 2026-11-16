"""
TRANSWORLD GIS & NOC TELEMETRY BACKEND SERVER
Connecting PostgreSQL (pgAdmin 4) to Transworld GIS Dashboard
Database: transworlddatabase
User: postgres
"""

import http.server
import socketserver
import json
import os
import re
import urllib.parse
from datetime import datetime
import psycopg2
from psycopg2.extras import RealDictCursor
import bcrypt
import time
import hashlib
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


def send_task_email(to_email, task_title, task_desc, region, deadline):
  try:
    print(f"[Mail Debug] Starting email dispatch process to: {to_email}")
    server_host = os.getenv('MAIL_SERVER', 'smtp.office365.com')
    port = int(os.getenv('MAIL_PORT', 587))
    user = os.getenv('MAIL_USERNAME')
    password = os.getenv('MAIL_PASSWORD')

    if not user or not password:
      print('[Mail Warning] Mail credentials missing in .env')
      return

    msg = MIMEMultipart()
    msg['From'] = user
    msg['To'] = to_email
    msg['Subject'] = f'New GIS Task Assigned: {task_title} ({region})'

    body = f"""
    Assalam-o-Alaikum,

    Aap ko Transworld GIS & NOC Dashboard par ek naya task assign kiya gaya hai.

    --- Task Details ---
    - Title: {task_title}
    - Region: {region}
    - Deadline: {deadline}
    - Description: {task_desc}

    Baraye meharbani dashboard par login kar ke isay check aur complete karein: http://127.0.0.1:5000

    Regards,
    Muhammad Hasaan Shafeeq (Boss / Lead Developer)
    Transworld Enterprise Services
    """
    msg.attach(MIMEText(body, 'plain'))

    # Connect to Outlook SMTP Server securely
    connection = smtplib.SMTP(server_host, port)
    connection.starttls()
    connection.login(user, password)
    connection.sendmail(user, to_email, msg.as_string())
    connection.quit()
    print(f'[Mail Success] Email successfully sent to {to_email}')
  except Exception as e:
    print(f'[Mail Error] Failed to send email to {to_email}: {e}')

from db_config import DB_CONFIG, PORT, ALLOWED_ORIGIN

DIRECTORY = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# Lightweight server-side session store: token -> {email, role, name, region, designation}
# ---------------------------------------------------------------------------
_sessions = {}
SESSION_IDLE_SECONDS = 8 * 60 * 60      # session expires after 8 hours of inactivity
MAX_LOGIN_FAILURES = 5                  # wrong passwords allowed before lockout
LOCKOUT_SECONDS = 5 * 60                # lockout length (5 minutes)
_login_failures = {}                    # email -> {"count": n, "locked_until": ts}


def _purge_expired_sessions():
    now = time.time()
    for tok in [t for t, s in _sessions.items() if now - s.get('last_seen', 0) > SESSION_IDLE_SECONDS]:
        _sessions.pop(tok, None)


def _lock_remaining(email):
    rec = _login_failures.get(email)
    if rec and rec.get('locked_until', 0) > time.time():
        return int(rec['locked_until'] - time.time()) + 1
    return 0


def _register_failure(email):
    rec = _login_failures.setdefault(email, {"count": 0, "locked_until": 0})
    if rec.get('locked_until', 0) and rec['locked_until'] <= time.time():
        rec['count'] = 0
        rec['locked_until'] = 0
    rec['count'] += 1
    if rec['count'] >= MAX_LOGIN_FAILURES:
        rec['locked_until'] = time.time() + LOCKOUT_SECONDS
        rec['count'] = 0

def _make_token(email):
    import secrets
    return secrets.token_hex(32)

def get_db_connection():
    try:
        conn = psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)
        return conn
    except Exception as e:
        print(f"[DB Error] Connection failed: {e}")
        return None

# Allowed constants for input validation
ALLOWED_STATUSES = ('Pending', 'In Progress', 'Submitted for Review', 'Accepted', 'Rejected')
ALLOWED_PRIORITIES = ('Low', 'Medium', 'High', 'Critical')
ALLOWED_TASK_TYPES = ('Survey Task', 'BOQ Task', 'Planning Task', 'Database Task')
ALLOWED_REGIONS = ('North', 'Central', 'South')

class TransworldAPIHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def _set_headers(self, status=200, content_type='application/json', extra_headers=None):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Access-Control-Allow-Origin', ALLOWED_ORIGIN)
        self.send_header('Access-Control-Allow-Credentials', 'true')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()

    def do_OPTIONS(self):
        self._set_headers(200)

    def _current_session(self):
        cookie = self.headers.get('Cookie', '')
        for part in cookie.split(';'):
            part = part.strip()
            if part.startswith('sid='):
                token = part[4:]
                sess = _sessions.get(token)
                if sess:
                    if time.time() - sess.get('last_seen', 0) > SESSION_IDLE_SECONDS:
                        _sessions.pop(token, None)
                        return None, token
                    sess['last_seen'] = time.time()
                return sess, token
        return None, None

    def _require_auth(self):
        sess, token = self._current_session()
        if not sess:
            self._set_headers(401)
            self.wfile.write(json.dumps({"error": "Authentication required. Please login."}).encode('utf-8'))
            return None
        return sess

    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path

        # Serve Dashboard frontend
        if path == '/' or path == '/index.html':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Access-Control-Allow-Origin', ALLOWED_ORIGIN)
            self.send_header('Access-Control-Allow-Credentials', 'true')
            self.end_headers()
            with open(os.path.join(DIRECTORY, 'index.html'), 'rb') as f:
                self.wfile.write(f.read())
            return

        # API: Test Database Connection (Public)
        if path == '/api/db-status':
            conn = get_db_connection()
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
                self._set_headers(200)
                self.wfile.write(json.dumps({
                    "status": "connected",
                    "database": DB_CONFIG["dbname"],
                    "message": "Connected to pgAdmin 4 (PostgreSQL) successfully!"
                }).encode('utf-8'))
            else:
                self._set_headers(500)
                self.wfile.write(json.dumps({
                    "status": "disconnected",
                    "error": "Could not connect to PostgreSQL. Check if PostgreSQL service is running."
                }).encode('utf-8'))
            return

        # API: Get all customers with live telemetry (Requires Auth)
        if path == '/api/customers':
            sess = self._require_auth()
            if not sess:
                return

            conn = get_db_connection()
            if not conn:
                self._set_headers(500)
                self.wfile.write(json.dumps({"error": "Database not reachable"}).encode('utf-8'))
                return

            try:
                with conn.cursor() as cur:
                    query = """
                    SELECT 
                        s.ont_id,
                        s.subscriber_name,
                        s.phone_number,
                        s.service_address,
                        s.building_name,
                        s.plot_no,
                        s.street_no,
                        s.block_name,
                        s.area_name,
                        s.sub_area,
                        s.city,
                        CAST(s.latitude AS FLOAT) AS lat,
                        CAST(s.longitude AS FLOAT) AS lng,
                        s.fat_id,
                        s.odb_id,
                        s.olt_name,
                        s.frame_no,
                        s.slot_no,
                        s.port_no,
                        s.ip_address,
                        s.mac_address,
                        s.bandwidth_plan,
                        s.bandwidth_mbps,
                        s.connection_status,
                        s.is_up,
                        s.last_down_cause,
                        s.current_alarm,
                        CAST(s.rx_ont_dbm AS FLOAT) AS rx_ont_dbm,
                        CAST(s.rx_olt_dbm AS FLOAT) AS rx_olt_dbm,
                        COALESCE(CAST(t.live_download_mbps AS FLOAT), 0.0) AS live_dl,
                        COALESCE(CAST(t.live_upload_mbps AS FLOAT), 0.0) AS live_ul,
                        COALESCE(t.bandwidth_utilization_pct, 0) AS load_pct,
                        COALESCE(CAST(t.latency_ms AS FLOAT), 11.2) AS latency_ms
                    FROM subscribers s
                    LEFT JOIN LATERAL (
                        SELECT live_download_mbps, live_upload_mbps, bandwidth_utilization_pct, latency_ms
                        FROM live_telemetry lt
                        WHERE lt.ont_id = s.ont_id
                        ORDER BY recorded_at DESC
                        LIMIT 1
                    ) t ON true
                    ORDER BY s.ont_id ASC;
                    """
                    cur.execute(query)
                    rows = cur.fetchall()
                    self._set_headers(200)
                    self.wfile.write(json.dumps(rows, default=str).encode('utf-8'))
            except Exception as e:
                conn.rollback()
                self._set_headers(500)
                self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))
            finally:
                conn.close()
            return

        # API: Network NOC Alarm Stats Summary (Requires Auth)
        if path == '/api/stats':
            sess = self._require_auth()
            if not sess:
                return

            conn = get_db_connection()
            if not conn:
                self._set_headers(500)
                self.wfile.write(json.dumps({"error": "Database not reachable"}).encode('utf-8'))
                return

            try:
                with conn.cursor() as cur:
                    query = """
                    SELECT 
                        COUNT(*) FILTER (WHERE connection_status = 'Online') AS online_count,
                        COUNT(*) FILTER (WHERE connection_status = 'Link Down') AS los_count,
                        COUNT(*) FILTER (WHERE connection_status = 'Powered Off') AS power_off_count,
                        COUNT(*) FILTER (WHERE connection_status = 'GEM Packet Loss') AS gem_loss_count,
                        COUNT(*) FILTER (WHERE connection_status = 'Low Optical Power') AS low_optical_count,
                        COUNT(*) AS total_subscribers,
                        ROUND(AVG(rx_ont_dbm), 2) AS avg_optical_power
                    FROM subscribers;
                    """
                    cur.execute(query)
                    row = cur.fetchone()
                    self._set_headers(200)
                    self.wfile.write(json.dumps(row, default=str).encode('utf-8'))
            except Exception as e:
                conn.rollback()
                self._set_headers(500)
                self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))
            finally:
                conn.close()
            return

        # API: Get Teams & Members (Requires Auth)
        if path == '/api/teams':
            sess = self._require_auth()
            if not sess:
                return

            conn = get_db_connection()
            if not conn:
                self._set_headers(500)
                self.wfile.write(json.dumps({"error": "Database not reachable"}).encode('utf-8'))
                return

            try:
                is_admin = (sess.get('role') == 'Boss')
                with conn.cursor() as cur:
                    if is_admin:
                        cur.execute("""
                            SELECT 
                                tm.member_id, tm.name, tm.email, tm.role, tm.region,
                                tm.designation, tm.phone, tm.avatar_color,
                                COUNT(ft.task_id) FILTER (WHERE ft.status IN ('Pending', 'In Progress', 'Submitted for Review')) AS active_tasks
                            FROM team_members tm
                            LEFT JOIN field_tasks ft ON tm.email = ft.assigned_to
                            GROUP BY tm.member_id, tm.name, tm.email, tm.role, tm.region, tm.designation, tm.phone, tm.avatar_color
                            ORDER BY 
                                CASE WHEN tm.role = 'Boss' THEN 1 ELSE 2 END,
                                tm.region ASC, tm.name ASC;
                        """)
                    else:
                        cur.execute("""
                            SELECT 
                                tm.member_id, tm.name,
                                CASE WHEN tm.email = %s THEN tm.email ELSE '' END AS email,
                                tm.role, tm.region, tm.designation,
                                CASE WHEN tm.email = %s THEN tm.phone ELSE '' END AS phone,
                                tm.avatar_color,
                                0 AS active_tasks
                            FROM team_members tm
                            ORDER BY 
                                CASE WHEN tm.role = 'Boss' THEN 1 ELSE 2 END,
                                tm.region ASC, tm.name ASC;
                        """, (sess['email'], sess['email']))
                    rows = cur.fetchall()
                    self._set_headers(200)
                    self.wfile.write(json.dumps(rows, default=str).encode('utf-8'))
            except Exception as e:
                conn.rollback()
                self._set_headers(500)
                self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))
            finally:
                conn.close()
            return

        # API: Get Field Tasks with Role Enforcement (Requires Auth)
        if path == '/api/tasks':
            sess = self._require_auth()
            if not sess:
                return

            conn = get_db_connection()
            if not conn:
                self._set_headers(500)
                self.wfile.write(json.dumps({"error": "Database not reachable"}).encode('utf-8'))
                return

            try:
                query_params = urllib.parse.parse_qs(parsed_path.query)
                status_filter = query_params.get('status', ['All'])[0]

                conditions = []
                params = []

                if sess.get('role') == 'Boss':
                    region_filter = query_params.get('region', ['All'])[0]
                    assignee_filter = query_params.get('assigned_to', [''])[0]
                    if region_filter and region_filter != 'All':
                        conditions.append("ft.region = %s")
                        params.append(region_filter)
                    if assignee_filter:
                        conditions.append("ft.assigned_to = %s")
                        params.append(assignee_filter)
                else:
                    conditions.append("ft.assigned_to = %s")
                    params.append(sess['email'])

                if status_filter and status_filter != 'All':
                    conditions.append("ft.status = %s")
                    params.append(status_filter)

                where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

                sql = f"""
                    SELECT 
                        ft.task_id, ft.task_code, ft.title, ft.task_type, ft.region,
                        ft.area_name, CAST(ft.latitude AS FLOAT) AS lat, CAST(ft.longitude AS FLOAT) AS lng,
                        ft.assigned_to, ft.assigned_by,
                        TO_CHAR(ft.deadline, 'YYYY-MM-DD HH24:MI') AS deadline_str,
                        ft.deadline, ft.priority, ft.status, ft.description,
                        ft.submission_notes, ft.report_filename, ft.boss_feedback,
                        TO_CHAR(ft.submitted_at, 'YYYY-MM-DD HH24:MI') AS submitted_at_str,
                        TO_CHAR(ft.reviewed_at, 'YYYY-MM-DD HH24:MI') AS reviewed_at_str,
                        TO_CHAR(ft.created_at, 'YYYY-MM-DD HH24:MI') AS created_at_str,
                        tm.name AS assignee_name, tm.designation AS assignee_designation,
                        tm.phone AS assignee_phone, tm.avatar_color
                    FROM field_tasks ft
                    LEFT JOIN team_members tm ON ft.assigned_to = tm.email
                    {where_clause}
                    ORDER BY 
                        CASE ft.status
                            WHEN 'Submitted for Review' THEN 1
                            WHEN 'In Progress' THEN 2
                            WHEN 'Pending' THEN 3
                            WHEN 'Rejected' THEN 4
                            WHEN 'Accepted' THEN 5
                            ELSE 6
                        END,
                        ft.deadline ASC;
                """
                with conn.cursor() as cur:
                    cur.execute(sql, tuple(params))
                    rows = cur.fetchall()
                    self._set_headers(200)
                    self.wfile.write(json.dumps(rows, default=str).encode('utf-8'))
            except Exception as e:
                conn.rollback()
                self._set_headers(500)
                self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))
            finally:
                conn.close()
            return

        # Block access to sensitive files, scripts, and database files
        BLOCKED_EXTENSIONS = ('.py', '.sql', '.pyc', '.env', '.txt', '.log', '.git', '.md', '.csv')
        lower_path = path.lower()
        if any(lower_path.endswith(ext) for ext in BLOCKED_EXTENSIONS) or '/.' in lower_path:
            self._set_headers(404)
            self.wfile.write(b'{"error": "File not found"}')
            return

        super().do_GET()

    def do_POST(self):
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path

        # ----------------------------------------------------------------
        # API: Login (Public)
        # ----------------------------------------------------------------
        if path == '/api/login':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            try:
                payload = json.loads(post_data.decode('utf-8'))
                email = payload.get('email', '').strip().lower()
                password = payload.get('password', '')

                if not email or not password:
                    self._set_headers(400)
                    self.wfile.write(json.dumps({"error": "Email and password are required"}).encode('utf-8'))
                    return

                wait = _lock_remaining(email)
                if wait:
                    self._set_headers(429)
                    self.wfile.write(json.dumps({"error": f"Too many failed attempts. Try again in {max(1, wait // 60 + (1 if wait % 60 else 0))} minute(s)."}).encode('utf-8'))
                    return

                conn = get_db_connection()
                if not conn:
                    self._set_headers(500)
                    self.wfile.write(json.dumps({"error": "Database connection failed"}).encode('utf-8'))
                    return

                try:
                    with conn.cursor() as cur:
                        cur.execute(
                            "SELECT name, email, role, region, designation, password_hash FROM team_members WHERE LOWER(email) = %s",
                            (email,)
                        )
                        member = cur.fetchone()
                except Exception as e:
                    conn.rollback()
                    self._set_headers(500)
                    self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))
                    return
                finally:
                    conn.close()

                if not member:
                    _register_failure(email)
                    self._set_headers(401)
                    self.wfile.write(json.dumps({"error": "Invalid email or password"}).encode('utf-8'))
                    return

                pw_hash = member.get('password_hash') or ''
                if not pw_hash:
                    self._set_headers(401)
                    self.wfile.write(json.dumps({"error": "Account has no password set. Contact administrator."}).encode('utf-8'))
                    return

                try:
                    match = bcrypt.checkpw(password.encode('utf-8'), pw_hash.encode('utf-8'))
                except Exception:
                    match = False

                if not match:
                    _register_failure(email)
                    self._set_headers(401)
                    self.wfile.write(json.dumps({"error": "Invalid email or password"}).encode('utf-8'))
                    return

                selected_region = payload.get('region', '').strip()
                if member['role'] != 'Boss' and selected_region:
                    if member['region'] != 'All' and member['region'].lower() != selected_region.lower():
                        self._set_headers(400)
                        self.wfile.write(json.dumps({"error": "This member does not belong to the selected region."}).encode('utf-8'))
                        return

                import secrets
                token = secrets.token_hex(32)
                _login_failures.pop(email, None)
                _purge_expired_sessions()
                sess = {
                    "last_seen": time.time(),
                    "email": member['email'],
                    "name": member['name'],
                    "role": member['role'],
                    "region": member['region'],
                    "designation": member.get('designation', ''),
                }
                _sessions[token] = sess

                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', ALLOWED_ORIGIN)
                self.send_header('Access-Control-Allow-Credentials', 'true')
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type')
                self.send_header('Set-Cookie', f'sid={token}; Path=/; SameSite=Lax; HttpOnly')
                self.end_headers()
                self.wfile.write(json.dumps({"status": "ok", "user": {k: v for k, v in sess.items() if k != "last_seen"}}).encode('utf-8'))
            except Exception as e:
                self._set_headers(400)
                self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))
            return

        # ----------------------------------------------------------------
        # API: Logout
        # ----------------------------------------------------------------
        if path == '/api/logout':
            sess, token = self._current_session()
            if token and token in _sessions:
                del _sessions[token]
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', ALLOWED_ORIGIN)
            self.send_header('Access-Control-Allow-Credentials', 'true')
            self.send_header('Set-Cookie', 'sid=; Path=/; Max-Age=0')
            self.end_headers()
            self.wfile.write(json.dumps({"status": "logged_out"}).encode('utf-8'))
            return

        # ----------------------------------------------------------------
        # API: Record Live Speed Telemetry (Admin Only)
        # ----------------------------------------------------------------
        if path == '/api/telemetry/record':
            sess = self._require_auth()
            if not sess:
                return
            if sess.get('role') != 'Boss':
                self._set_headers(403)
                self.wfile.write(json.dumps({"error": "Access denied: only Admin can record telemetry"}).encode('utf-8'))
                return

            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            try:
                payload = json.loads(post_data.decode('utf-8'))
                ont_id = payload.get('ont_id')
                dl = float(payload.get('download_mbps', 0))
                ul = float(payload.get('upload_mbps', 0))
                pct = int(payload.get('load_pct', 0))
                lat = float(payload.get('latency_ms', 11.0))

                conn = get_db_connection()
                if not conn:
                    self._set_headers(500)
                    self.wfile.write(json.dumps({"error": "Database connection failed"}).encode('utf-8'))
                    return

                try:
                    with conn.cursor() as cur:
                        cur.execute("""
                            INSERT INTO live_telemetry (ont_id, live_download_mbps, live_upload_mbps, bandwidth_utilization_pct, latency_ms)
                            VALUES (%s, %s, %s, %s, %s);
                        """, (ont_id, dl, ul, pct, lat))
                        conn.commit()
                except Exception as e:
                    conn.rollback()
                    self._set_headers(500)
                    self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))
                    return
                finally:
                    conn.close()

                self._set_headers(200)
                self.wfile.write(json.dumps({"status": "recorded", "ont_id": ont_id}).encode('utf-8'))
            except Exception as e:
                self._set_headers(400)
                self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))
            return

        # ----------------------------------------------------------------
        # API: Add New Customer into PostgreSQL (Admin Only, No overwrite)
        # ----------------------------------------------------------------
        if path == '/api/customer/add':
            sess = self._require_auth()
            if not sess:
                return
            if sess.get('role') != 'Boss':
                self._set_headers(403)
                self.wfile.write(json.dumps({"error": "Access denied: only Admin can add customers"}).encode('utf-8'))
                return

            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            try:
                c = json.loads(post_data.decode('utf-8'))
                ont_id = c.get('ont_id', '').strip()
                subscriber_name = c.get('subscriber_name', '').strip()
                if not ont_id or not subscriber_name:
                    self._set_headers(400)
                    self.wfile.write(json.dumps({"error": "ont_id and subscriber_name are required"}).encode('utf-8'))
                    return

                conn = get_db_connection()
                if not conn:
                    self._set_headers(500)
                    self.wfile.write(json.dumps({"error": "Database connection failed"}).encode('utf-8'))
                    return

                try:
                    with conn.cursor() as cur:
                        cur.execute("SELECT 1 FROM subscribers WHERE ont_id = %s;", (ont_id,))
                        if cur.fetchone():
                            self._set_headers(409)
                            self.wfile.write(json.dumps({"error": f"Customer with ont_id '{ont_id}' already exists"}).encode('utf-8'))
                            return

                        fat_val = c.get('fat_id') or None
                        odb_val = c.get('odb_id') or None

                        cur.execute("""
                            INSERT INTO subscribers (
                                ont_id, subscriber_name, phone_number, service_address, area_name, city,
                                latitude, longitude, fat_id, odb_id, bandwidth_plan, bandwidth_mbps,
                                connection_status, is_up, rx_ont_dbm, rx_olt_dbm
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
                        """, (
                            ont_id, subscriber_name, c.get('phone_number', ''),
                            c.get('service_address', 'Eden Valley'),
                            c.get('area_name', 'Eden Valley'), c.get('city', 'Islamabad'),
                            c.get('lat', 31.4357), c.get('lng', 73.1549),
                            fat_val, odb_val,
                            c.get('bandwidth_plan', '40MB'),
                            int(c.get('bandwidth_mbps', 40)), c.get('connection_status', 'Online'),
                            c.get('is_up', True), float(c.get('rx_ont_dbm', -21.5)), float(c.get('rx_olt_dbm', -23.1))
                        ))
                        conn.commit()
                except Exception as e:
                    conn.rollback()
                    self._set_headers(500)
                    self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))
                    return
                finally:
                    conn.close()

                self._set_headers(200)
                self.wfile.write(json.dumps({"status": "success", "ont_id": ont_id}).encode('utf-8'))
            except Exception as e:
                self._set_headers(400)
                self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))
            return

        # ----------------------------------------------------------------
        # API: Create New Task (Admin Only) - WITH GUARANTEED EMAIL TRIGGER
        # ----------------------------------------------------------------
        if path == '/api/tasks/create':
            sess = self._require_auth()
            if not sess:
                return
            if sess.get('role') != 'Boss':
                self._set_headers(403)
                self.wfile.write(json.dumps({"error": "Access denied: only Admin can create tasks"}).encode('utf-8'))
                return

            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            try:
                payload = json.loads(post_data.decode('utf-8'))
                title = payload.get('title', '').strip()
                task_type = payload.get('task_type', 'Survey Task').strip()
                region = payload.get('region', 'North').strip()
                assigned_to = payload.get('assigned_to', '').strip().lower()
                deadline_str = payload.get('deadline', '').strip()
                priority = payload.get('priority', 'Medium').strip()
                area_name = payload.get('area_name', '').strip()
                lat = payload.get('latitude')
                lng = payload.get('longitude')
                description = payload.get('description', '').strip()
                assigned_by = sess['email']

                if not title or not assigned_to or not deadline_str:
                    self._set_headers(400)
                    self.wfile.write(json.dumps({"error": "Title, assigned_to, and deadline are required"}).encode('utf-8'))
                    return

                if task_type not in ALLOWED_TASK_TYPES:
                    self._set_headers(400)
                    self.wfile.write(json.dumps({"error": f"Invalid task_type. Must be one of: {ALLOWED_TASK_TYPES}"}).encode('utf-8'))
                    return

                if region not in ALLOWED_REGIONS:
                    self._set_headers(400)
                    self.wfile.write(json.dumps({"error": f"Invalid region. Must be one of: {ALLOWED_REGIONS}"}).encode('utf-8'))
                    return

                if priority not in ALLOWED_PRIORITIES:
                    self._set_headers(400)
                    self.wfile.write(json.dumps({"error": f"Invalid priority. Must be one of: {ALLOWED_PRIORITIES}"}).encode('utf-8'))
                    return

                try:
                    clean_d = deadline_str.replace('T', ' ')[:16]
                    deadline_dt = datetime.strptime(clean_d, '%Y-%m-%d %H:%M')
                except ValueError:
                    self._set_headers(400)
                    self.wfile.write(json.dumps({"error": "Invalid deadline format. Use YYYY-MM-DD HH:MM"}).encode('utf-8'))
                    return

                conn = get_db_connection()
                if not conn:
                    self._set_headers(500)
                    self.wfile.write(json.dumps({"error": "Database connection failed"}).encode('utf-8'))
                    return

                try:
                    with conn.cursor() as cur:
                        cur.execute("SELECT email, region, role FROM team_members WHERE LOWER(email) = %s;", (assigned_to,))
                        assignee_row = cur.fetchone()
                        if not assignee_row:
                            self._set_headers(400)
                            self.wfile.write(json.dumps({"error": f"Assignee '{assigned_to}' does not exist in team_members"}).encode('utf-8'))
                            return

                        if assignee_row['role'] != 'Boss' and assignee_row['region'] != 'All':
                            if assignee_row['region'].lower() != region.lower():
                                self._set_headers(400)
                                self.wfile.write(json.dumps({"error": f"Assignee region '{assignee_row['region']}' does not match task region '{region}'"}).encode('utf-8'))
                                return

                        cur.execute("SELECT nextval('task_code_seq');")
                        seq_val = cur.fetchone()['nextval']
                        reg_code = region[:3].upper()
                        task_code = f"TSK-{reg_code}-{seq_val:04d}"

                        cur.execute("""
                            INSERT INTO field_tasks (
                                task_code, title, task_type, region, area_name,
                                latitude, longitude, assigned_to, assigned_by,
                                deadline, priority, status, description
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'Pending', %s)
                            RETURNING task_id, task_code;
                        """, (
                            task_code, title, task_type, region, area_name,
                            lat, lng, assigned_to, assigned_by,
                            deadline_dt, priority, description
                        ))
                        new_task = cur.fetchone()
                        conn.commit()
                except Exception as e:
                    conn.rollback()
                    self._set_headers(500)
                    self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))
                    return
                finally:
                    conn.close()

                # GUARANTEED EMAIL CALL AFTER DB CLOSE
                print(f"[DEBUG API] Task created successfully in DB. Triggering email to {assigned_to}...")
                send_task_email(
                    to_email=assigned_to,
                    task_title=title,
                    task_desc=description,
                    region=region,
                    deadline=deadline_str
                )

                self._set_headers(200)
                self.wfile.write(json.dumps({"status": "created", "task": new_task}).encode('utf-8'))
            except Exception as e:
                self._set_headers(400)
                self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))
            return

        # ----------------------------------------------------------------
        # API: Member Status Update (Start / Submit)
        # ----------------------------------------------------------------
        if path == '/api/tasks/update-status':
            sess = self._require_auth()
            if not sess:
                return

            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            try:
                payload = json.loads(post_data.decode('utf-8'))
                task_id = payload.get('task_id')
                new_status = payload.get('status', '').strip()
                notes = payload.get('submission_notes', '')
                report_fn = payload.get('report_filename', '')

                if not task_id:
                    self._set_headers(400)
                    self.wfile.write(json.dumps({"error": "task_id is required"}).encode('utf-8'))
                    return

                allowed_member_statuses = ('In Progress', 'Submitted for Review')
                if new_status not in allowed_member_statuses:
                    self._set_headers(403)
                    self.wfile.write(json.dumps({"error": f"Status '{new_status}' cannot be set by Member"}).encode('utf-8'))
                    return

                conn = get_db_connection()
                if not conn:
                    self._set_headers(500)
                    self.wfile.write(json.dumps({"error": "Database connection failed"}).encode('utf-8'))
                    return

                try:
                    with conn.cursor() as cur:
                        cur.execute("SELECT task_id, status, assigned_to FROM field_tasks WHERE task_id = %s;", (task_id,))
                        task_row = cur.fetchone()
                        if not task_row:
                            self._set_headers(404)
                            self.wfile.write(json.dumps({"error": f"Task {task_id} not found"}).encode('utf-8'))
                            return

                        if sess.get('role') != 'Boss':
                            if task_row['assigned_to'] != sess['email']:
                                self._set_headers(403)
                                self.wfile.write(json.dumps({"error": "Access denied: this task is not assigned to you"}).encode('utf-8'))
                                return

                        if new_status == 'Submitted for Review':
                            cur.execute("""
                                UPDATE field_tasks
                                SET status = %s,
                                    submission_notes = COALESCE(NULLIF(%s, ''), submission_notes),
                                    report_filename = COALESCE(NULLIF(%s, ''), report_filename),
                                    boss_feedback = NULL,
                                    reviewed_at = NULL,
                                    submitted_at = CURRENT_TIMESTAMP,
                                    updated_at = CURRENT_TIMESTAMP
                                WHERE task_id = %s;
                            """, (new_status, notes, report_fn, task_id))
                        else:
                            cur.execute("""
                                UPDATE field_tasks
                                SET status = %s,
                                    submission_notes = COALESCE(NULLIF(%s, ''), submission_notes),
                                    updated_at = CURRENT_TIMESTAMP
                                WHERE task_id = %s;
                            """, (new_status, notes, task_id))
                        conn.commit()
                except Exception as e:
                    conn.rollback()
                    self._set_headers(500)
                    self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))
                    return
                finally:
                    conn.close()

                self._set_headers(200)
                self.wfile.write(json.dumps({"status": "updated", "task_id": task_id, "new_status": new_status}).encode('utf-8'))
            except Exception as e:
                self._set_headers(400)
                self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))
            return

        # ----------------------------------------------------------------
        # API: Admin Review (Accept / Reject) — Boss ONLY
        # ----------------------------------------------------------------
        if path == '/api/tasks/review':
            sess = self._require_auth()
            if not sess:
                return
            if sess.get('role') != 'Boss':
                self._set_headers(403)
                self.wfile.write(json.dumps({"error": "Access denied: only Admin can accept or reject tasks"}).encode('utf-8'))
                return

            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            try:
                payload = json.loads(post_data.decode('utf-8'))
                task_id = payload.get('task_id')
                decision = payload.get('decision', '').strip()
                feedback = payload.get('boss_feedback', '').strip()

                if not task_id:
                    self._set_headers(400)
                    self.wfile.write(json.dumps({"error": "task_id is required"}).encode('utf-8'))
                    return

                if decision not in ['Accepted', 'Rejected']:
                    self._set_headers(400)
                    self.wfile.write(json.dumps({"error": "Decision must be 'Accepted' or 'Rejected'"}).encode('utf-8'))
                    return

                conn = get_db_connection()
                if not conn:
                    self._set_headers(500)
                    self.wfile.write(json.dumps({"error": "Database connection failed"}).encode('utf-8'))
                    return

                try:
                    with conn.cursor() as cur:
                        cur.execute("SELECT task_id, status FROM field_tasks WHERE task_id = %s;", (task_id,))
                        task_row = cur.fetchone()
                        if not task_row:
                            self._set_headers(404)
                            self.wfile.write(json.dumps({"error": f"Task {task_id} not found"}).encode('utf-8'))
                            return

                        if task_row['status'] != 'Submitted for Review':
                            self._set_headers(400)
                            self.wfile.write(json.dumps({
                                "error": f"Cannot review task in '{task_row['status']}' status. Only 'Submitted for Review' tasks can be reviewed."
                            }).encode('utf-8'))
                            return

                        cur.execute("""
                            UPDATE field_tasks
                            SET status = %s,
                                boss_feedback = %s,
                                reviewed_at = CURRENT_TIMESTAMP,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE task_id = %s;
                        """, (decision, feedback, task_id))
                        conn.commit()
                except Exception as e:
                    conn.rollback()
                    self._set_headers(500)
                    self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))
                    return
                finally:
                    conn.close()

                self._set_headers(200)
                self.wfile.write(json.dumps({"status": "reviewed", "task_id": task_id, "decision": decision}).encode('utf-8'))
            except Exception as e:
                self._set_headers(400)
                self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))
            return

        self._set_headers(404)
        self.wfile.write(json.dumps({"error": "Endpoint not found"}).encode('utf-8'))

if __name__ == '__main__':
    print("================================================================")
    print(" TRANSWORLD NOC & GIS BACKEND API SERVER")
    print(f" Connecting to PostgreSQL: {DB_CONFIG['dbname']} on port {DB_CONFIG['port']}")
    print("================================================================")

    test_conn = get_db_connection()
    if test_conn:
        print(" [SUCCESS] Connected to PostgreSQL database successfully!")
        test_conn.close()
    else:
        print(" [WARNING] Database connection failed. Verify PostgreSQL credentials.")

    server_address = ('127.0.0.1', PORT)
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(server_address, TransworldAPIHandler) as httpd:
        print(f" [RUNNING] Server listening at: http://127.0.0.1:{PORT}")
        print(" Open http://localhost:5000 in your browser!")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n [STOPPED] Server shut down.")