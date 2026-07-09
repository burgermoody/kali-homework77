# 用户管理系统 — 两天完整漏洞总结（7月8日 ~ 7月9日）

---

## 📅 Day 1（7月8日）— 初始安全审计：13项已修复

| # | 漏洞 | 严重度 | 说明 | 状态 |
|---|------|--------|------|------|
| 1 | 密码明文存储 | 🔴高危 | `USERS` 字典直接存明文 `"admin123"` | ✅ 修复 |
| 2 | 密码明文比对 | 🔴高危 | `==` 直接比较，时序攻击风险 | ✅ 修复 |
| 3 | 密码泄露到模板 | 🔴高危 | 登录后将 `password` 传给 `{{ user.password }}` | ✅ 修复 |
| 4 | HTML 注释泄露账号 | 🔴高危 | `<!-- admin/admin123 -->` 硬编码在模板中 | ✅ 修复 |
| 5 | 弱密码哈希 | 🟡低危 | 原使用 MD5/SHA-1 | ✅ 修复 |
| 6 | 弱 secret_key | 🟠中危 | `app.secret_key = "dev-key-2025"` 硬编码 | ✅ 修复 |
| 7 | Debug 模式 | 🟠中危 | Werkzeug 调试控制台暴露 | ⚠️ **今日回归** |
| 8 | 无 CSRF 防护 | 🔴高危 | 表单无 csrf_token、登出为 GET | ✅ 修复 |
| 9 | Session 无安全标志 | 🟠中危 | 缺 HttpOnly/SameSite | ✅ 修复 |
| 10 | SESSION_PERMANENT 缺失 | 🟡低危 | 未启用 | ✅ 修复 |
| 11 | GET 登出 CSRF | 🔴高危 | `<img src="/logout">` 可强制登出 | ✅ 修复 |
| 12 | 无频率限制 | 🟡低危 | 登录可无限暴力破解 | ✅ 修复 |
| 13 | 无输入校验 | 🟡低危 | 表单未清洗 | ✅ 修复 |
| 14 | 错误信息过度精确 | 🟡低危 | 可区分"用户不存在"/"密码错误" | ✅ 修复 |

---

## 📅 Day 2（7月8日）— 新增 SQLite 功能：5项有意遗留

新增路由 `/search`（GET 搜索）、`/register`（POST 注册），使用 SQLite 数据库。

| # | 漏洞 | 位置 | 严重度 | SQL 代码 | 说明 |
|---|------|------|--------|---------|------|
| 15 | **搜索 SQL 注入** | `app.py:254` | 🔴高危 | `f"SELECT ... LIKE '%{keyword}%'"` | 搜索框 f-string 直拼，可 UNION/OR/盲注 |
| 16 | **注册 SQL 注入** | `app.py:233` | 🔴高危 | `f"INSERT INTO users VALUES ('{username}', ...)"` | 注册表单 f-string 直拼，可闭包注入 |
| 17 | SQL 泄露到控制台 | `app.py:234,255` | 🟡低危 | `print(f"[SQL] {sql}")` | SQL 语句打印到 stdout |
| 18 | 注册输入无过滤 | `app.py:224-227` | 🟡低危 | 直接拼接 username/email/phone | 无 `_sanitize_input()` 调用 |
| 19 | 搜索输入无过滤 | `app.py:250` | 🟡低危 | 直接拼接 keyword | 无 `_sanitize_input()` 调用 |

### 已验证的 SQL 注入攻击类型

| 攻击类型 | 向量 | 效果 |
|---------|------|------|
| **UNION 注入** | `' UNION SELECT 1,username,email,phone FROM users--` | 窃取所有用户数据 |
| **OR 注入** | `' OR '1'='1` | 返回全部用户（绕过搜索限制） |
| **闭包注入** | `hacker', 'pw', 'h@x.com', '123'), ('admin2',...` | INSERT 插入多条记录 |
| **UPSERT 覆盖密码** | `x') ON CONFLICT DO UPDATE SET password='hacked'--` | 覆盖任意用户密码 |
| **布尔盲注** | `' OR (SELECT substr(password,1,1) ...)='$'--` | 逐字符猜解密码哈希 |
| **时间盲注** | `' OR (CASE WHEN ... THEN 1 ELSE randomblob(50000000) END)--` | 通过延迟判断条件 |
| **堆叠查询** | `' ; DROP TABLE users;--` | ❌ SQLite 不允许（无害） |
| **表结构窃取** | `' UNION SELECT 1,name,sql,4 FROM sqlite_master--` | 获取所有表名和 DDL |

---

## 📅 Day 3（7月9日）— 今日新增上传功能：新发现4项问题

### 新增路由：`/upload`（文件上传）
- 文件: `app.py:274-298`, `templates/upload.html`
- 登录用户可上传头像文件

### 新发现漏洞

| # | 漏洞 | 位置 | 严重度 | 说明 |
|---|------|------|--------|------|
| **🆕20** | **文件上传路径遍历** | `app.py:294` | 🔴高危 | `f.filename` 未清洗，`os.path.join` 后直接 `f.save()`。若文件名为 `../../etc/cron.d/job` 或 `/etc/passwd`，可写入任意路径。`os.path.join(UPLOAD_FOLDER, "/etc/passwd")` → `/etc/passwd`（绝对路径丢弃前缀） |
| **🆕21** | **无文件类型校验** | `app.py:289-295` | 🟠中危 | 无扩展名/Content-Type/MIME 校验，可上传 .exe、.php、.html 等任意文件到服务端 |
| **🆕22** | **Debug 模式回归** | `app.py:310` | 🟠中危 | `app.run(debug=True, ...)` 硬编码，Werkzeug 调试控制台重新暴露。行 23 的 `DEBUG` 环境变量是死代码，从未被使用 |
| **🆕23** | **上传文件 URL 注入** | `app.py:296` | 🟡低危 | `url_for("static", filename=f"uploads/{f.filename}")` 同样使用未清洗的 filename，可能用于 URL 操纵 |

### 遗留的 5 项 SQL 注入（同上 Day 2 的 #15-#19）

---

## 📊 总览

| 维度 | Day 1（7/8） | Day 2（7/8） | Day 3（7/9） | 合计 |
|------|:-----------:|:-----------:|:-----------:|:----:|
| ✅ 已修复 | 13 | 0 | 0 | **13** |
| ⚠️ 回归 | 0 | 0 | 1（Debug） | **1** |
| 🆕 新增未修复 | 0 | 0 | 3（上传） | **3** |
| 🎯 有意遗留 | 0 | 5（SQL注入） | 0 | **5** |
| **总计漏洞** | **13** | **5** | **4** | **22** |

### 当前仍存在的漏洞（共 9 项）

| 严重度 | 数量 | 明细 |
|--------|:----:|------|
| 🔴 高危 | 4 | 搜索 SQL 注入 · 注册 SQL 注入 · 上传路径遍历 · Debug 模式暴露 |
| 🟠 中危 | 2 | 无文件类型校验 · Debug 模式回归 |
| 🟡 低危 | 3 | SQL 日志泄露 · 注册无过滤 · 搜索无过滤 |
| 🔴+🟡 | 9 | **总计 9 项未修复漏洞** |

---

## 🔧 修复建议

### 上传路径遍历修复
```python
# ❌ 有漏洞
save_path = os.path.join(UPLOAD_FOLDER, f.filename)

# ✅ 安全修复
import re
from werkzeug.utils import secure_filename

safe_name = secure_filename(f.filename)  # 移除 ../ 、绝对路径、特殊字符
if not safe_name:
    error = "文件名不合法"
else:
    save_path = os.path.join(UPLOAD_FOLDER, safe_name)
    f.save(save_path)
```

### 文件类型校验
```python
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# 使用前校验
if not allowed_file(f.filename):
    error = "仅允许图片文件"
```

### Debug 模式修复
```python
# 行 310 改为
app.run(debug=DEBUG, host="0.0.0.0", port=5000)
# 或用
app.run(host="0.0.0.0", port=5000)  # 完全移除 debug 参数
```

### SQL 注入修复（同 Day 2 报告）
```python
# 搜索 — 参数化查询
c.execute("SELECT ... WHERE username LIKE ? OR email LIKE ?",
          ('%' + keyword + '%', '%' + keyword + '%'))

# 注册 — 参数化查询
c.execute("INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
          (username, hashed_pw, email, phone))
```
