# 用户信息管理平台 — 安全漏洞修复报告

**项目名称**：用户信息管理平台（Flask）  
**报告日期**：2026-07-07  
**状态**：✅ 全部修复完成，11/11 测试通过  

---

## 一、漏洞扫描概况

对项目 5 个文件（`app.py`、`base.html`、`login.html`、`index.html`、`style.css`）进行了全面安全审计，共发现 **11 项安全漏洞**，涉及：

| 严重程度 | 数量 |
|---------|------|
| 🔴 高危 | 4 |
| 🟠 中危 | 4 |
| 🟡 低危 | 3 |

---

## 二、漏洞详情与修复方案

### 🔴 CWE-256：密码明文存储与明文比对

**漏洞描述**  
密码以明文形式存储在 `USERS` 字典中（如 `"admin123"`），登录时使用 `==` 直接进行字符串比对。攻击者若获得数据库访问权限即可直接获取所有用户明文密码。

**涉及文件**  
`app.py`（USERS 字典、login 函数）

**修复方案**  
- 使用 `werkzeug.security.generate_password_hash()` 对密码进行 bcrypt 哈希存储
- 使用 `werkzeug.security.check_password_hash()` 进行安全的哈希比对，消除时序攻击风险

```python
# 修复前
USERS = {"admin": {"password": "admin123"}}
if USERS[username]["password"] == password: ...

# 修复后
USERS = {"admin": {"password": generate_password_hash("admin123")}}
if user and check_password_hash(user["password"], password): ...
```

---

### 🔴 CWE-200：密码泄露至模板并显示在页面上

**漏洞描述**  
登录后，用户的完整信息（含 `password` 字段）被直接传递给模板，并在 `index.html` 中以明文 `{{ user.password }}` 渲染。

**涉及文件**  
`app.py`（index 路由、login 路由）、`index.html`

**修复方案**  
- 传递模板前，使用字典推导排除 `password` 字段
- 模板中密码单元格固定显示 `••••••••`（`&bull;` 实体）

```python
# 修复前
return render_template("index.html", user=USERS[username])

# 修复后
user_info = {k: v for k, v in USERS[username].items() if k != "password"}
return render_template("index.html", user=user_info, username=username)
```

```html
<!-- 修复前 -->
<td class="info-value">{{ user.password }}</td>

<!-- 修复后 -->
<td class="info-value">&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;</td>
```

---

### 🔴 CWE-615：HTML 注释泄露默认管理员账号

**漏洞描述**  
`login.html` 和 `base.html` 顶部包含 HTML 注释，硬编码了管理员用户名 `admin` 和密码 `admin123`。任何查看页面源码的人均可获取。

**涉及文件**  
`login.html`、`base.html`

**修复方案**  
删除所有包含敏感信息的 HTML 注释。

```html
<!-- 修复前：存在于 login.html 和 base.html -->
<!-- 调试信息 - 默认管理员账号 用户名: admin 密码: admin123 -->

<!-- 修复后：已删除 -->
```

---

### 🔴 CWE-352：跨站请求伪造（CSRF）

**漏洞描述**  
登录表单无 CSRF 令牌验证，`/logout` 为 GET 路由且无任何防护。攻击者可构造恶意页面诱导用户登录或登出。

**涉及文件**  
`app.py`、`login.html`、`base.html`、`index.html`

**修复方案**  
- 实现 CSRF 令牌生成器 `_generate_csrf_token()`，存储在 session 中
- 登录表单添加隐藏字段 `<input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">`
- 服务端校验 `request.form.get("_csrf_token")` 与 `session["_csrf_token"]` 是否一致
- `/logout` 改为 POST-only，同样校验 CSRF 令牌

```python
def _generate_csrf_token() -> str:
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]

app.jinja_env.globals["csrf_token"] = _generate_csrf_token

# 登录时校验
csrf_input = request.form.get("_csrf_token", "")
csrf_session = session.get("_csrf_token", "")
if not csrf_session or csrf_input != csrf_session:
    abort(403, "CSRF token 无效，请刷新页面重试")
```

```html
<!-- 修复后：退出改为 POST 表单 -->
<form method="post" action="/logout" class="inline-form">
    <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
    <button type="submit" class="nav-link-btn">退出</button>
</form>
```

---

### 🟠 CWE-798：弱密钥硬编码

**漏洞描述**  
`secret_key` 硬编码为 `"dev-key-2025"`，该值固定且可被轻易猜测，攻击者可利用它伪造会话 cookie。

**涉及文件**  
`app.py`

**修复方案**  
优先从环境变量 `SECRET_KEY` 读取密钥；未设置时回退到 `secrets.token_hex(32)` 生成 256 位随机密钥。

```python
# 修复前
app.secret_key = "dev-key-2025"

# 修复后
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
```

---

### 🟠 CWE-489：Debug 模式硬编码

**漏洞描述**  
`debug=True` 硬编码在 `app.run()` 中，生产环境中会暴露 Werkzeug 调试控制台，允许远程代码执行。

**涉及文件**  
`app.py`

**修复方案**  
Debug 模式由环境变量 `FLASK_DEBUG` 控制（`"1"` 为开启，任何其他值均为关闭）。

```python
# 修复前
app.run(debug=True, host="0.0.0.0", port=5000)

# 修复后
DEBUG = os.environ.get("FLASK_DEBUG", "0") == "1"
app.run(debug=DEBUG, host="0.0.0.0", port=5000)
```

---

### 🟠 CWE-614：Session Cookie 缺少安全标志

**漏洞描述**  
Session cookie 未设置 `HttpOnly` 和 `SameSite` 标志，存在 XSS 窃取 cookie 和 CSRF 利用风险。

**涉及文件**  
`app.py`

**修复方案**  
在 Flask 配置中显式设置安全标志和过期时间。

```python
# 修复后
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,      # 禁止 JS 读取 cookie
    SESSION_COOKIE_SAMESITE="Lax",     # 防止跨站请求携带 cookie
    SESSION_COOKIE_SECURE=False,       # 生产环境应设为 True（HTTPS）
    SESSION_PERMANENT=True,            # 使 PERMANENT_SESSION_LIFETIME 生效
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
)
```

---

### 🟡 CWE-307：登录频率限制缺失

**漏洞描述**  
登录接口无任何频率限制，攻击者可进行暴力破解尝试。

**涉及文件**  
`app.py`

**修复方案**  
基于 IP 地址记录失败次数，连续失败 5 次后锁定该 IP 15 分钟。

```python
LOGIN_ATTEMPTS = {}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

def _is_locked_out(ip):
    record = LOGIN_ATTEMPTS.get(ip)
    if not record:
        return False
    if record.get("locked_until") and time.time() < record["locked_until"]:
        return True
    # 锁定时间已过则自动解除
    ...

def _record_failed_attempt(ip):
    record = LOGIN_ATTEMPTS.setdefault(ip, {"count": 0, "locked_until": 0})
    record["count"] += 1
    if record["count"] >= MAX_LOGIN_ATTEMPTS:
        record["locked_until"] = time.time() + LOCKOUT_MINUTES * 60
```

---

### 🟡 CWE-20：输入校验缺失

**漏洞描述**  
表单输入未经任何清洗和校验，用户名和密码未限制长度。

**涉及文件**  
`app.py`、`login.html`

**修复方案**  
- 实现 `_sanitize_input()` 函数清洗用户输入：去除首尾空白、限制 64 字符长度、移除不可打印控制字符
- 在 HTML 表单中添加 `maxlength` 属性

```python
def _sanitize_input(value, max_len=64):
    if not isinstance(value, str):
        return ""
    value = value.strip()[:max_len]
    return "".join(c for c in value if c.isprintable())
```

```html
<input type="text" name="username" maxlength="64" required>
<input type="password" name="password" maxlength="128" required>
```

---

### 🟡 CWE-200：错误信息过度精确

**漏洞描述**  
登录失败时可直接区分"用户不存在"和"密码错误"两种情形，为攻击者提供了用户枚举渠道。

**涉及文件**  
`app.py`

**修复方案**  
统一返回模糊化错误信息"用户名或密码错误"，不区分具体失败原因。

```python
# 修复后
user = USERS.get(username)
if user and check_password_hash(user["password"], password):
    # 登录成功
    ...
else:
    # 无论用户不存在还是密码错误，均返回相同提示
    error = "用户名或密码错误"
```

---

### 🟢 补充修复：SESSION_PERMANENT 配置缺失

**发现方式**  
代码审查中发现 `PERMANENT_SESSION_LIFETIME=timedelta(hours=2)` 已配置，但 Flask 全局配置 `SESSION_PERMANENT` 未显式设置。虽然登录时 `session.permanent = True` 使 TTL 生效，但配置不明确易导致后续维护者误解。

**修复**  
在 `app.config.update()` 中显式添加 `SESSION_PERMANENT=True`。

---

## 三、修复前后对比汇总

| 漏洞 | CWE | 严重程度 | 修复前 | 修复后 |
|------|-----|---------|--------|--------|
| 密码明文存储 | 256 | 🔴高危 | `"admin123"` 明文 | `generate_password_hash()` 哈希 |
| 密码明文比对 | 256 | 🔴高危 | `==` 字符串比对 | `check_password_hash()` |
| 密码显示在页面 | 200 | 🔴高危 | `{{ user.password }}` | `••••••••` |
| HTML 注释泄露账号 | 615 | 🔴高危 | `<!-- admin/admin123 -->` | 已删除 |
| 弱 secret_key | 798 | 🟠中危 | `"dev-key-2025"` | 环境变量 / `secrets.token_hex(32)` |
| Debug 模式硬编码 | 489 | 🟠中危 | `debug=True` | `FLASK_DEBUG` 环境变量 |
| Session 无安全标志 | 614 | 🟠中危 | 无配置 | HttpOnly + SameSite=Lax |
| 无 CSRF 防护 | 352 | 🟠中危 | 无 token | 隐藏 token + 服务端校验 |
| 无频率限制 | 307 | 🟡低危 | 无限重试 | 5 次失败锁定 15 分钟 |
| 无输入校验 | 20 | 🟡低危 | 无限制 | 去空白、限长、去控制字符 |
| 错误信息精确 | 200 | 🟡低危 | 区分原因 | 统一"用户名或密码错误" |
| SESSION_PERMANENT 缺失 | — | 🟢补充 | 未配置 | `SESSION_PERMANENT=True` |

---

## 四、回归测试结果

修复完成后，通过自动化测试对 11 个维度进行了验证：

| # | 测试项 | 结果 |
|---|-------|------|
| 1 | 首页未登录显示"请先登录" | ✅ PASS |
| 2 | HTML 注释不泄露账号密码 | ✅ PASS |
| 3 | `SESSION_PERMANENT=True` 配置 | ✅ PASS |
| 4 | `GET /logout` 返回 405 | ✅ PASS |
| 5 | `POST /logout` 无 CSRF 返回 403 | ✅ PASS |
| 6 | admin 登录成功 + 密码遮盖 | ✅ PASS |
| 7 | CSRF 保护下 POST 登出 + session 清除 | ✅ PASS |
| 8 | 错误密码返回模糊提示 | ✅ PASS |
| 9 | 空输入校验 | ✅ PASS |
| 10 | alice 用户正常登录 | ✅ PASS |
| 11 | 频率限制（5 次失败后锁定） | ✅ PASS |

**测试结论**：全部 11 项通过 ✅

---

## 五、修复文件清单

| 文件 | 路径 | 行数 | 变更类型 |
|------|------|------|---------|
| app.py | `/home/user/user_management/app.py` | 154 | 重写 |
| base.html | `/home/user/user_management/templates/base.html` | 30 | 修改 |
| login.html | `/home/user/user_management/templates/login.html` | 29 | 修改 |
| index.html | `/home/user/user_management/templates/index.html` | 52 | 修改 |
| style.css | `/home/user/user_management/static/css/style.css` | 259 | 新增样式 |

---

## 六、安全建议（后续改进）

1. **持久化存储**：当前 `USERS` 字典和 `LOGIN_ATTEMPTS` 均为内存存储，服务重启后数据丢失。建议后续接入 `data_store.py` 或 SQLite 实现持久化。
2. **HTTPS 部署**：生产环境应将 `SESSION_COOKIE_SECURE` 设为 `True`，并配置 SSL/TLS 证书。
3. **日志审计**：建议添加登录日志记录（成功/失败、IP、时间戳），便于事后追溯。
4. **验证码机制**：在频率限制基础上，增加图形验证码或 reCAPTCHA 进一步提升暴力破解难度。
