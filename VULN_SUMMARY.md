# 用户管理系统 — 漏洞总清单（完整版）

**项目阶段**：两天完整安全审计  
**涉及文件**：`app.py`、`base.html`、`login.html`、`index.html`、`register.html`、`style.css`  
**测试结果**：共发现 **18 项安全漏洞/缺陷**，其中已修复 13 项，已知遗留 5 项

---

## 一、漏洞分类统计

| 类别 | 数量 | 严重程度分布 |
|------|------|-------------|
| 🔴 高危漏洞 | 7 | 密码明文、密码泄露、CSRF、SQL注入等 |
| 🟠 中危漏洞 | 6 | Session 安全、Debug 模式、弱密钥等 |
| 🟡 低危漏洞 | 5 | 信息泄露、输入校验、频率控制等 |
| **合计** | **18** | |

---

## 二、漏洞详细清单

### 第一组：身份认证与密码安全（Day 1）

| # | 漏洞名称 | CWE | 严重程度 | 说明 | 状态 |
|---|---------|-----|---------|------|------|
| 1 | **密码明文存储** | CWE-256 | 🔴高危 | `USERS` 字典中直接存储 `"admin123"` 明文密码 | ✅ 已修复 |
| 2 | **密码明文比对** | CWE-256 | 🔴高危 | 使用 `==` 直接比较字符串，存在时序攻击风险 | ✅ 已修复 |
| 3 | **密码泄露到模板** | CWE-200 | 🔴高危 | 登录后将 `password` 字段传给模板并渲染为 `{{ user.password }}` | ✅ 已修复 |
| 4 | **HTML 注释泄露账号** | CWE-615 | 🔴高危 | `login.html` 和 `base.html` 有 `<!-- admin/admin123 -->` 注释 | ✅ 已修复 |
| 5 | **弱密码哈希算法** | — | 🟡低危 | 原使用 MD5/SHA-1 等弱算法（修复后升级为 scrypt） | ✅ 已修复 |

### 第二组：Web 安全基础防护（Day 1）

| # | 漏洞名称 | CWE | 严重程度 | 说明 | 状态 |
|---|---------|-----|---------|------|------|
| 6 | **弱 secret_key** | CWE-798 | 🟠中危 | `app.secret_key = "dev-key-2025"` 硬编码固定值 | ✅ 已修复 |
| 7 | **Debug 模式硬编码** | CWE-489 | 🟠中危 | `debug=True` 暴露 Werkzeug 调试控制台 | ✅ 已修复 |
| 8 | **无 CSRF 防护** | CWE-352 | 🔴高危 | 登录表单无 CSRF token，`/logout` 为 GET 路由 | ✅ 已修复 |
| 9 | **Session 无安全标志** | CWE-614 | 🟠中危 | 缺少 HttpOnly、SameSite 等 cookie 安全标志 | ✅ 已修复 |
| 10 | **SESSION_PERMANENT 缺失** | — | 🟡低危 | `PERMANENT_SESSION_LIFETIME` 设置了但全局配置未启用 | ✅ 已修复 |
| 11 | **GET 登出 CSRF** | CWE-352 | 🔴高危 | `<img src="/logout">` 可强制用户登出 | ✅ 已修复 |

### 第三组：暴力破解与输入安全（Day 1）

| # | 漏洞名称 | CWE | 严重程度 | 说明 | 状态 |
|---|---------|-----|---------|------|------|
| 12 | **无频率限制** | CWE-307 | 🟡低危 | 登录接口可无限暴力破解 | ✅ 已修复 |
| 13 | **无输入校验** | CWE-20 | 🟡低危 | 表单输入未经清洗和长度限制 | ✅ 已修复 |
| 14 | **错误信息过度精确** | CWE-200 | 🟡低危 | 可区分"用户不存在"和"密码错误" | ✅ 已修复 |

### 第四组：SQL 注入漏洞（Day 2 — 新增功能）

| # | 漏洞名称 | CWE | 严重程度 | 说明 | 状态 |
|---|---------|-----|---------|------|------|
| 15 | **搜索功能 SQL 注入** | CWE-89 | 🔴高危 | `f"SELECT ... WHERE username LIKE '%{keyword}%'"` 使用 f-string 拼接用户输入 | ⚠️ 已知遗留 |
| 16 | **注册功能 SQL 注入** | CWE-89 | 🔴高危 | `f"INSERT INTO users VALUES ('{username}', ...)"` 使用 f-string 拼接 | ⚠️ 已知遗留 |
| 17 | **SQL 语句打印到控制台** | CWE-532 | 🟡低危 | `print(f"[SQL] {sql}")` 泄露 SQL 语句到日志 | ⚠️ 已知遗留 |
| 18 | **注册输入无过滤** | CWE-20 | 🟡低危 | 注册表单的 username/email/phone 直接拼入 SQL | ⚠️ 已知遗留 |

---

## 三、SQL 注入 POC 验证结果

### POC 1：UNION 注入 ✅

```sql
-- 输入
keyword = ' UNION SELECT 1,'inj','inj@x.com','138'--

-- 生成的 SQL
SELECT id, username, email, phone FROM users
WHERE username LIKE '%' UNION SELECT 1,'inj','inj@x.com','138'--%'
       OR email LIKE '%' UNION SELECT 1,'inj','inj@x.com','138'--%'

-- 结果：搜索结果中出现攻击者伪造的 inj/inj@x.com
```

### POC 2：OR 万能条件 ✅

```sql
-- 输入
keyword = ' OR '1'='1

-- 生成的 SQL
SELECT ... WHERE username LIKE '%' OR '1'='1%' OR email LIKE '%' OR '1'='1%'

-- 结果：返回 users 表全部用户（admin、alice 等）
```

### POC 3：UNION 窃取全部数据 ✅

```sql
-- 输入
keyword = ' UNION SELECT 1,username,email,phone FROM users--

-- 生成的 SQL
SELECT ... WHERE username LIKE '%' UNION SELECT 1,username,email,phone FROM users--%'

-- 结果：获取数据库中所有用户的用户名和邮箱
```

---

## 四、缺陷分布热力图

```
文件                🔴高危  🟠中危  🟡低危  合计
─────────────────────────────────────────────
app.py               5      3      3     11
templates/base.html  1      0      0      1
templates/login.html 1      0      0      1
templates/index.html 0      0      0      0
templates/register.html 0   0      0      0
static/css/style.css 0      0      0      0
─────────────────────────────────────────────
合计                 7      3      3     13（已修复）
新增遗留              2      0      3      5（SQL注入相关）
总计                 9      3      6     18
```

---

## 五、修复状态总结

| 阶段 | 已修复 | 已知遗留 | 合计 |
|------|-------|---------|------|
| Day 1：初始漏洞 | 13 | 0 | 13 |
| Day 2：新增功能 | 0 | 5 | 5 |
| **总计** | **13** | **5** | **18** |

### 遗留的 5 个漏洞（均为 SQL 注入相关）

```
1. 🔴 搜索功能 SQL 注入（f-string 拼接）
2. 🔴 注册功能 SQL 注入（f-string 拼接）
3. 🟡 SQL 日志泄露到控制台
4. 🟡 注册用户名无过滤
5. 🟡 搜索关键词无过滤

注：以上 5 项为教学演示目的有意保留
```

---

## 六、从攻击者视角看漏洞利用链

```
攻击入口
    │
    ├─ 1. 未登录访问 /search?keyword=注入语句
    │     └─ UNION SELECT 窃取所有用户数据
    │
    ├─ 2. 注册页面注入
    │     └─ 在 username 字段插入 SQL 代码
    │
    ├─ 3. 暴力破解登录（已修复 → 频率限制 + 延迟锁）
    │
    ├─ 4. CSRF 攻击（已修复 → CSRF token 校验）
    │
    └─ 5. Session 劫持（已修复 → HttpOnly + SameSite）
```

---

## 七、修复建议（针对 SQL 注入）

将 f-string 拼接改为参数化查询即可消除剩余 5 个漏洞：

```python
# ❌ 有漏洞（当前）
sql = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
c.execute(sql)

# ✅ 安全（参数化查询）
c.execute("SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?",
          ('%' + keyword + '%', '%' + keyword + '%'))
```

```python
# ❌ 有漏洞（当前）
sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{hashed_pw}', '{email}', '{phone}')"
c.execute(sql)

# ✅ 安全（参数化查询）
c.execute("INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
          (username, hashed_pw, email, phone))
```
