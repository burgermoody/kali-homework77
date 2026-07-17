import os
import secrets
import time
import sqlite3
from datetime import timedelta

from flask import Flask, render_template, request, redirect, session, abort, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import urllib.request, urllib.error
import subprocess, platform
import re, json

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
    SESSION_PERMANENT=True,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
)

DEBUG = os.environ.get("FLASK_DEBUG", "0") == "1"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_DIR = os.path.join(BASE_DIR, 'data')
DB_PATH = os.path.join(DB_DIR, 'users.db')
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')


def init_db():
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        phone TEXT,
        balance REAL DEFAULT 0,
        role TEXT DEFAULT 'user'
    )''')
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, balance, role) VALUES (?, ?, ?, ?, ?, ?)",
              ('admin', generate_password_hash('admin123'), 'admin@example.com', '13800138000', 99999, 'admin'))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, balance, role) VALUES (?, ?, ?, ?, ?, ?)",
              ('alice', generate_password_hash('alice2025'), 'alice@example.com', '13900139001', 100, 'user'))
    # 兼容旧表：如 balance/role 列不存在则添加
    try:
        c.execute("ALTER TABLE users ADD COLUMN balance REAL DEFAULT 0")
    except:
        pass
    try:
        c.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
    except:
        pass
    conn.commit()
    conn.close()
    print("[init_db] 数据库初始化完成")


USERS = {
    "admin": {
        "username": "admin",
        "password": generate_password_hash("admin123"),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
    },
    "alice": {
        "username": "alice",
        "password": generate_password_hash("alice2025"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
    },
}

LOGIN_ATTEMPTS = {}
MAX_LOGIN_ATTEMPTS = 7
LOCKOUT_MINUTES = 5
COUNTER_TTL = 15 * 60
BASE_DELAY = 0.3


def _is_locked_out(ip):
    record = LOGIN_ATTEMPTS.get(ip)
    if not record:
        return False
    if record.get("locked_until") and time.time() < record["locked_until"]:
        return True
    if record["locked_until"] and time.time() >= record["locked_until"]:
        del LOGIN_ATTEMPTS[ip]
        return False
    return False


def _record_failed_attempt(ip):
    now = time.time()
    record = LOGIN_ATTEMPTS.setdefault(ip, {"count": 0, "locked_until": 0, "last_fail": 0})
    if now - record["last_fail"] > COUNTER_TTL:
        record["count"] = 0
    record["count"] += 1
    record["last_fail"] = now
    if record["count"] >= MAX_LOGIN_ATTEMPTS:
        record["locked_until"] = now + LOCKOUT_MINUTES * 60


def _clear_attempts(ip):
    LOGIN_ATTEMPTS.pop(ip, None)


def _login_delay(ip):
    record = LOGIN_ATTEMPTS.get(ip)
    count = record["count"] if record else 0
    dynamic = min(0.5 * (2 ** (count - 1)), 8.0) if count > 0 else 0
    total = BASE_DELAY + dynamic
    time.sleep(total)


def _sanitize_input(value, max_len=64):
    if not isinstance(value, str):
        return ""
    value = value.strip()[:max_len]
    return "".join(c for c in value if c.isprintable())


def _get_user_info(username):
    if not username:
        return None
    if username in USERS:
        return {k: v for k, v in USERS[username].items() if k != "password"}
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT username, email, phone FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()
        if row:
            return {"username": row[0], "email": row[1], "phone": row[2]}
    except:
        pass
    return None


def _get_user_by_id(user_id):
    """根据 user_id 查询用户资料（含余额）"""
    try:
        uid = int(user_id)
    except (ValueError, TypeError):
        return None
    # 先从 SQLite 查询
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT id, username, email, phone, balance, role FROM users WHERE id = ?", (uid,))
        row = c.fetchone()
        conn.close()
        if row:
            return {
                "id": row[0],
                "username": row[1],
                "email": row[2],
                "phone": row[3],
                "balance": row[4],
                "role": row[5],
            }
    except:
        pass
    return None


def _update_balance(user_id, amount):
    """更新用户余额：balance = balance + amount"""
    try:
        uid = int(user_id)
        amt = float(amount)
    except (ValueError, TypeError):
        return False
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amt, uid))
        conn.commit()
        conn.close()
        return True
    except:
        return False


def _validate_csrf():
    csrf_input = request.form.get("_csrf_token", "")
    csrf_session = session.get("_csrf_token", "")
    if not csrf_session or csrf_input != csrf_session:
        abort(403, "CSRF token 无效")


def _generate_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


app.jinja_env.globals["csrf_token"] = _generate_csrf_token


@app.before_request
def _refresh_session():
    if session.get("username"):
        session.permanent = True


@app.route("/")
def index():
    username = session.get("username")
    user_info = _get_user_info(username)
    return render_template("index.html", user=user_info, username=username)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    success = request.args.get("registered")

    if request.method == "POST":
        _validate_csrf()

        client_ip = request.remote_addr or "unknown"
        if _is_locked_out(client_ip):
            error = f"登录失败次数过多，账号已被临时锁定 {LOCKOUT_MINUTES} 分钟"
            return render_template("login.html", error=error, success=success)

        _login_delay(client_ip)
        username = _sanitize_input(request.form.get("username", ""))
        password = request.form.get("password", "")

        if not username or not password:
            error = "用户名和密码不能为空"
            return render_template("login.html", error=error, success=success)

        login_ok = False
        user = USERS.get(username)
        if user and check_password_hash(user["password"], password):
            login_ok = True
        else:
            try:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute("SELECT * FROM users WHERE username = ?", (username,))
                row = c.fetchone()
                conn.close()
                if row and check_password_hash(row[2], password):
                    login_ok = True
            except:
                pass

        if login_ok:
            session["username"] = username
            session.permanent = True
            _clear_attempts(client_ip)
            user_info = _get_user_info(username)
            return render_template("index.html", user=user_info, username=username)
        else:
            _record_failed_attempt(client_ip)
            error = "用户名或密码错误"

    session.pop("_csrf_token", None)
    return render_template("login.html", error=error, success=success)


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None

    if request.method == "POST":
        _validate_csrf()

        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")

        if not username or not password:
            error = "用户名和密码不能为空"
        else:
            hashed_pw = generate_password_hash(password)
            sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{hashed_pw}', '{email}', '{phone}')"
            print(f"[SQL] {sql}")
            try:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute(sql)
                conn.commit()
                conn.close()
                return redirect(url_for("login", registered="注册成功，请登录"))
            except Exception as e:
                error = f"注册失败：{str(e)}"

    return render_template("register.html", error=error)


@app.route("/search", methods=["GET"])
def search():
    keyword = request.args.get("keyword", "")
    results = []

    if keyword:
        sql = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
        print(f"[SQL] {sql}")
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute(sql)
            rows = c.fetchall()
            conn.close()
            for row in rows:
                results.append({"id": row[0], "username": row[1], "email": row[2], "phone": row[3]})
        except:
            pass

    username = session.get("username")
    user_info = _get_user_info(username)

    return render_template("index.html", user=user_info, username=username,
                           search_results=results, search_keyword=keyword)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    """用户头像上传"""
    if "username" not in session:
        return redirect(url_for("login"))

    uploaded_url = None
    error = None

    if request.method == "POST":
        _validate_csrf()

        if "file" not in request.files:
            error = "没有选择文件"
        else:
            f = request.files["file"]
            if f.filename == "":
                error = "没有选择文件"
            else:
                os.makedirs(UPLOAD_FOLDER, exist_ok=True)
                safe_name = secure_filename(f.filename)
                if not safe_name:
                    error = "文件名不合法"
                else:
                    save_path = os.path.join(UPLOAD_FOLDER, safe_name)
                    f.save(save_path)
                    uploaded_url = url_for("static", filename=f"uploads/{safe_name}")

    return render_template("upload.html", uploaded_url=uploaded_url, error=error)


@app.route("/profile", methods=["GET"])
def profile():
    """个人中心 — 根据 user_id 查询用户资料，不验证登录身份"""
    if "username" not in session:
        return redirect(url_for("login"))

    user_id = request.args.get("user_id")
    if not user_id:
        return "缺少 user_id 参数", 400

    user_info = _get_user_by_id(user_id)
    if not user_info:
        return "用户不存在", 404

    return render_template("profile.html", user=user_info)


@app.route("/recharge", methods=["POST"])
def recharge():
    """充值 — 直接增加余额，不做正负校验"""
    if "username" not in session:
        return redirect(url_for("login"))

    _validate_csrf()
    user_id = request.form.get("user_id")
    amount = request.form.get("amount")

    if not user_id or amount is None:
        return "缺少参数", 400

    _update_balance(user_id, amount)
    return redirect(url_for("profile", user_id=user_id))


@app.route("/page", methods=["GET"])
def page():
    """动态页面加载 — 安全版本：限制文件读取在 pages/ 目录内"""
    name = request.args.get("name", "")

    if not name:
        page_content = "请指定页面名称"
    else:
        # 安全检查：拒绝包含 ../ 的路径
        if ".." in name or "/" in name:
            page_content = "页面不存在"
        else:
            # 只允许 pages/ 目录下的 .html 文件
            pages_dir = os.path.join(BASE_DIR, "pages")
            file_path = os.path.join(pages_dir, name + ".html")
            # 规范化路径确保在 pages 目录内
            real_path = os.path.realpath(file_path)
            if real_path.startswith(os.path.realpath(pages_dir) + os.sep) and os.path.isfile(real_path):
                with open(real_path, "r", encoding="utf-8") as f:
                    page_content = f.read()
            else:
                page_content = "页面不存在"

    username = session.get("username")
    user_info = _get_user_info(username)
    return render_template("index.html", user=user_info, username=username,
                           page_content=page_content)


@app.route("/change-password", methods=["POST"])
def change_password():
    """修改密码 — 需要 CSRF Token 验证，防止跨站请求伪造"""
    if "username" not in session:
        return redirect(url_for("login"))

    _validate_csrf()

    username = request.form.get("username")
    new_password = request.form.get("new_password")

    if not username or not new_password:
        return "用户名和密码不能为空", 400

    hashed_pw = generate_password_hash(new_password)

    # 更新 USERS 字典中的密码
    if username in USERS:
        USERS[username]["password"] = hashed_pw

    # 更新 SQLite 数据库中的密码
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_pw, username))
        conn.commit()
        conn.close()
    except:
        pass

    return redirect(url_for("profile", user_id=request.form.get("user_id", "1")))


@app.route("/fetch-url", methods=["POST"])
def fetch_url():
    """URL 抓取 — 安全版本：限制协议并阻止内网地址"""
    if "username" not in session:
        return redirect(url_for("login"))

    url = request.form.get("url", "").strip()
    if not url:
        fetch_status = "错误"
        fetch_content = "请提供 URL"

    if url:
        # 只允许 http 和 https 协议
        if not url.startswith(("http://", "https://")):
            fetch_status = "错误"
            fetch_content = "不支持的 URL 协议，仅允许 http:// 和 https://"
        else:
            # 解析目标主机名，阻止内网地址
            try:
                from urllib.parse import urlparse
                import socket
                parsed = urlparse(url)
                hostname = parsed.hostname
                if not hostname:
                    fetch_status = "错误"
                    fetch_content = "无效的 URL"
                else:
                    ip = socket.gethostbyname(hostname)
                    # 检查是否为内网地址
                    if ip.startswith(("127.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
                                      "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                                      "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                                      "172.30.", "172.31.", "192.168.", "169.254.", "0.")) or ip == "::1":
                        fetch_status = "错误"
                        fetch_content = f"不允许访问内网地址：{ip}"
                    else:
                        try:
                            req = urllib.request.Request(url)
                            with urllib.request.urlopen(req, timeout=10) as resp:
                                code = resp.getcode()
                                fetch_status = f"{code}" if code is not None else "200"
                                raw = resp.read()
                                content = raw.decode("utf-8", errors="replace")
                                if len(content) > 5000:
                                    content = content[:5000] + "\n\n...（仅显示前 5000 字符）"
                                fetch_content = content
                        except urllib.error.HTTPError as e:
                            fetch_status = f"{e.code} {e.reason}"
                            fetch_content = str(e.read().decode("utf-8", errors="replace"))
                        except Exception as e:
                            fetch_status = "错误"
                            fetch_content = str(e)
            except socket.gaierror:
                fetch_status = "错误"
                fetch_content = f"无法解析主机名"
            except Exception as e:
                fetch_status = "错误"
                fetch_content = str(e)

    username = session.get("username")
    user_info = _get_user_info(username)
    return render_template("index.html", user=user_info, username=username,
                           fetch_status=fetch_status, fetch_content=fetch_content,
                           fetch_url=url)


@app.route("/ping", methods=["GET", "POST"])
def ping():
    """Ping 网络诊断 — 安全版本：校验输入为合法IP或域名"""
    if "username" not in session:
        return redirect(url_for("login"))

    result = None
    ip = ""

    if request.method == "POST":
        ip = request.form.get("ip", "").strip()
        if ip:
            # 安全检查：只允许合法IP地址或域名（字母、数字、点、短横、冒号）
            import re
            if not re.match(r'^[a-zA-Z0-9.\-:]+$', ip):
                result = "错误：输入包含非法字符，仅允许 IP 地址或域名"
            else:
                try:
                    cmd = ["ping", "-c", "3", ip]
                    output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=30)
                    result = output.decode("utf-8", errors="replace")
                except subprocess.CalledProcessError as e:
                    result = e.output.decode("utf-8", errors="replace")
                except subprocess.TimeoutExpired:
                    result = "Ping 超时（30 秒）"
                except Exception as e:
                    result = f"执行错误：{str(e)}"

    return render_template("ping.html", result=result, ip=ip)


@app.route("/xml-import", methods=["GET", "POST"])
def xml_import():
    """XML 数据导入 — 支持 XXE，读取本地文件"""
    if "username" not in session:
        return redirect(url_for("login"))

    result = None
    error = None
    xml_data = ""

    if request.method == "POST":
        xml_data = request.form.get("xml_data", "")

        if xml_data:
            try:
                # 检测 XML 中的实体定义，提取 SYSTEM 文件路径
                entity_pattern = re.compile(r'<!ENTITY\s+\S+\s+SYSTEM\s+[\'"]([^\'"]+)[\'"]')
                entity_match = entity_pattern.search(xml_data)
                file_path = None
                file_content = ""

                if entity_match:
                    file_path = entity_match.group(1)
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            file_content = f.read().strip()
                    except Exception as e:
                        file_content = f"读取文件失败：{str(e)}"

                # 替换实体引用 &xxe; 为文件内容
                if file_content:
                    xml_data = re.sub(r'&xxe;', file_content, xml_data)
                    xml_data = re.sub(r'&xxe2;', file_content, xml_data)

                # 解析 XML 提取用户数据
                import xml.etree.ElementTree as ET
                root = ET.fromstring(xml_data)
                users = []
                for user_elem in root.findall("user"):
                    name = user_elem.findtext("name", "")
                    email = user_elem.findtext("email", "")
                    users.append({"name": name, "email": email})

                result = json.dumps({"users": users}, ensure_ascii=False, indent=2)

            except ET.ParseError as e:
                error = f"XML 解析错误：{str(e)}"
            except Exception as e:
                error = f"处理失败：{str(e)}"

    return render_template("xml_import.html", result=result, error=error, xml_data=xml_data)


@app.route("/logout", methods=["POST"])
def logout():
    _validate_csrf()
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    init_db()
    app.run(debug=DEBUG, host="0.0.0.0", port=5000)
