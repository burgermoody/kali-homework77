import os
import secrets
import time
from datetime import timedelta

from flask import Flask, render_template, request, redirect, session, abort
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# ========== [修复] 安全密钥：优先从环境变量读取，回退到 secrets 生成 ==========
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# ========== [修复] Session 安全加固 ==========
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
    SESSION_PERMANENT=True,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
)

# ========== [修复] Debug 模式由环境变量控制 ==========
DEBUG = os.environ.get("FLASK_DEBUG", "0") == "1"

# ========== [修复] 密码哈希存储（不再是明文！）==========
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

# ========== [修复] 登录频率限制 ==========
LOGIN_ATTEMPTS = {}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


def _is_locked_out(ip: str) -> bool:
    record = LOGIN_ATTEMPTS.get(ip)
    if not record:
        return False
    if record.get("locked_until") and time.time() < record["locked_until"]:
        return True
    if record["locked_until"] and time.time() >= record["locked_until"]:
        del LOGIN_ATTEMPTS[ip]
        return False
    return False


def _record_failed_attempt(ip: str):
    record = LOGIN_ATTEMPTS.setdefault(ip, {"count": 0, "locked_until": 0})
    record["count"] += 1
    if record["count"] >= MAX_LOGIN_ATTEMPTS:
        record["locked_until"] = time.time() + LOCKOUT_MINUTES * 60


def _clear_attempts(ip: str):
    LOGIN_ATTEMPTS.pop(ip, None)


def _sanitize_input(value: str, max_len: int = 64) -> str:
    if not isinstance(value, str):
        return ""
    value = value.strip()[:max_len]
    return "".join(c for c in value if c.isprintable())


# ========== [修复] CSRF 令牌 ==========
def _generate_csrf_token() -> str:
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


app.jinja_env.globals["csrf_token"] = _generate_csrf_token


@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = {k: v for k, v in USERS[username].items() if k != "password"}
    return render_template("index.html", user=user_info, username=username)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        # ---- CSRF 校验 ----
        csrf_input = request.form.get("_csrf_token", "")
        csrf_session = session.get("_csrf_token", "")
        if not csrf_session or csrf_input != csrf_session:
            abort(403, "CSRF token 无效，请刷新页面重试")

        # ---- IP 封禁检测 ----
        client_ip = request.remote_addr or "unknown"
        if _is_locked_out(client_ip):
            error = f"登录失败次数过多，账号已被临时锁定 {LOCKOUT_MINUTES} 分钟"
            return render_template("login.html", error=error)

        # ---- 输入清洗 ----
        username = _sanitize_input(request.form.get("username", ""))
        password = request.form.get("password", "")

        if not username or not password:
            error = "用户名和密码不能为空"
            return render_template("login.html", error=error)

        # ---- [修复] 安全的哈希比对 ----
        user = USERS.get(username)
        if user and check_password_hash(user["password"], password):
            session["username"] = username
            session.permanent = True
            user_info = {k: v for k, v in user.items() if k != "password"}
            _clear_attempts(client_ip)
            return render_template("index.html", user=user_info, username=username)
        else:
            _record_failed_attempt(client_ip)
            error = "用户名或密码错误"

    return render_template("login.html", error=error)


@app.route("/logout", methods=["POST"])
def logout():
    # [修复] POST-only + CSRF 校验，防止 GET 方式强制注销
    csrf_input = request.form.get("_csrf_token", "")
    csrf_session = session.get("_csrf_token", "")
    if not csrf_session or csrf_input != csrf_session:
        abort(403, "CSRF token 无效")
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(debug=DEBUG, host="0.0.0.0", port=5000)
