# 跨站请求伪造（CSRF）漏洞安全报告 — 分析与修复

**审计日期**：2026-07-14  
**审计范围**：全站所有 POST 路由  
**涉及文件**：`app.py`、`templates/profile.html`  
**应用地址**：http://192.168.31.128:5000

---

## 一、漏洞概述

| 项目 | 内容 |
|------|------|
| **漏洞类型** | 跨站请求伪造（CSRF / CWE-352） |
| **漏洞位置** | `POST /change-password` 路由 |
| **风险等级** | **🔴 高危** |
| **CVSS 评分** | **8.8**（AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H） |

### CVSS 3.1 评分分项拆解

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H

┌────────────┬────┬──────────────────────────────────────┐
│ 攻击向量   │ AV:N │ 远程网络攻击                          │
│ 攻击复杂度 │ AC:L │ 无需特殊条件                          │
│ 权限要求   │ PR:N │ 无需用户账号                          │
│ 用户交互   │ UI:R │ 需要受害者点击链接或访问恶意页面       │
│ 影响范围   │ S:U  │ 仅影响本组件                          │
│ 机密性     │ C:H  │ 攻击者可登录目标账号查看敏感资料       │
│ 完整性     │ I:H  │ 攻击者可修改目标密码，完全接管账号     │
│ 可用性     │ A:H  │ 账号被改密码后原用户无法登录           │
└────────────┴────┴──────────────────────────────────────┘
```

---

## 二、CSRF 漏洞原理

### 什么是 CSRF？

跨站请求伪造（Cross-Site Request Forgery）攻击者通过构造恶意页面，在受害者已登录目标网站的情况下，诱使受害者的浏览器自动发起恶意请求，从而在受害者不知情的情况下执行非法操作。

```
受害者（已登录目标网站）
   │
   ├─ 访问攻击者构造的恶意页面
   │     └─ 页面中包含自动提交表单 / 图片标签 / XHR 请求
   │
   └─ 浏览器自动携带目标网站的 Cookie
         └─ 请求到达目标服务器
               └─ 服务器无法区分请求来源 → 执行恶意操作
```

### 本应用 CSRF 防护现状（修复前）

| 路由 | 方法 | CSRF Token | 状态 |
|------|:----:|:-----------:|:----:|
| `/login` | POST | ✅ `_validate_csrf()` | ✅ 安全 |
| `/register` | POST | ✅ `_validate_csrf()` | ✅ 安全 |
| `/upload` | POST | ✅ `_validate_csrf()` | ✅ 安全 |
| `/recharge` | POST | ✅ `_validate_csrf()` | ✅ 安全 |
| `/logout` | POST | ✅ `_validate_csrf()` | ✅ 安全 |
| **`/change-password`** | **POST** | **❌ 无校验** | **🔴 漏洞** |

---

## 三、漏洞详情

### 漏洞位置：`/change-password` 路由

**问题代码（修复前）：**

```python
@app.route("/change-password", methods=["POST"])
def change_password():
    """修改密码 — 不需要原密码、不需要 CSRF Token、不限目标用户"""
    if "username" not in session:
        return redirect(url_for("login"))

    # ❌ 缺少 _validate_csrf() 调用

    username = request.form.get("username")
    new_password = request.form.get("new_password")
    ...
```

**问题表单（修复前）：**

```html
<form method="post" action="/change-password" class="change-password-form">
    <!-- ❌ 缺少 _csrf_token 隐藏字段 -->
    <input type="hidden" name="username" value="{{ user.username }}">
    ...
```

---

## 四、攻击向量分析

### POC 1：攻击者构造恶意 HTML 页面

攻击者创建一个简单的 HTML 页面，受害者访问后自动修改密码：

```html
<html>
<body>
<h1>点击领奖</h1>
<form id="csrfForm" method="post" action="http://192.168.31.128:5000/change-password">
    <input type="hidden" name="username" value="admin">
    <input type="hidden" name="new_password" value="attacker123">
    <input type="hidden" name="user_id" value="1">
    <input type="submit" value="领取奖品">
</form>
<script>
    // 或者自动提交，无需用户点击
    document.getElementById('csrfForm').submit();
</script>
</body>
</html>
```

### POC 2：通过图片标签自动发起请求

```html
<!-- 利用 CSS 隐藏 iframe，利用图片标签无法发送 POST 的限制，
     但可以使用表单 + JavaScript 自动提交 -->
<img src="x" onerror="
    var f=document.createElement('form');
    f.method='POST';f.action='http://192.168.31.128:5000/change-password';
    f.innerHTML='<input name=username value=admin><input name=new_password value=hacked123>';
    document.body.appendChild(f);f.submit();
">
```

### POC 3：CSRF 结合越权攻击

前面的任务故意保留了"任何已登录用户可修改任何人的密码"功能，这使得 CSRF 攻击的破坏力加倍：

```
攻击者构造页面 → 受害者 admin 访问 → 自动 POST /change-password
→ username=alice, new_password=attacker123
→ alice 的密码被改为 attacker123
→ 攻击者用 attacker123 登录 alice
→ 查看 alice 的余额、资料等敏感信息
```

### 修复前验证结果

| 测试用例 | 结果 |
|---------|:----:|
| 不带 CSRF Token 修改密码 | ✅ 成功修改（漏洞！） |
| 带错误 CSRF Token 修改密码 | ✅ 成功修改（漏洞！） |
| 从外部页面自动提交表单 | ✅ 密码被篡改（漏洞！） |

---

## 五、漏洞影响分析

### 攻击场景 1：账号完全接管

```
1. 攻击者在论坛/评论区发布恶意链接
2. 管理员（已登录本系统）点击链接
3. 恶意页面自动 POST /change-password
4. 管理员密码被改为攻击者指定的值
5. 攻击者用新密码登录 → 完全接管管理员账号
6. 查看所有用户资料、余额，修改其他用户密码
```

### 攻击场景 2：批量账号劫持

```
1. 攻击者通过搜索功能收集用户列表（admin、alice...）
2. 构造恶意页面，遍历 username 参数批量提交
3. 受害者只要访问一次，所有关联账号密码被篡改
```

### 攻击场景 3：结合其他漏洞

```
CSRF 修改密码 + 越权充值（IDOR）
   ├─ 修改 admin 密码 → 登录 admin → 查看/充值任意用户
   ├─ 修改 alice 密码 → 登录 alice → 窃取余额
   └─ 修改任意用户密码 → 完全控制该用户
```

### 攻击场景 4：CSRF + XSS 联动攻击

```
⚠️ 如果系统存在 XSS 漏洞，CSRF 防护可能被绕过：

1. 攻击者利用 XSS 注入脚本读取当前页面的 CSRF Token
2. 脚本构造带有效 Token 的 POST 请求
3. 请求看起来完全合法 → 服务器无法区分
4. 结论：CSRF Token 无法防御来自同源的请求
   → 必须先修复 XSS 漏洞，CSRF 防护才能真正生效
```

---

## 六、修复方案

### 修复代码

```python
@app.route("/change-password", methods=["POST"])
def change_password():
    """修改密码 — 需要 CSRF Token 验证，防止跨站请求伪造"""
    if "username" not in session:
        return redirect(url_for("login"))

    _validate_csrf()  # ✅ 添加 CSRF Token 校验

    username = request.form.get("username")
    new_password = request.form.get("new_password")
    ...
```

### 修复表单

```html
<form method="post" action="/change-password" class="change-password-form">
    <!-- ✅ 添加 CSRF Token -->
    <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
    <input type="hidden" name="username" value="{{ user.username }}">
    <input type="hidden" name="user_id" value="{{ user.id }}">
    ...
```

### 修复策略

| 防护措施 | 说明 |
|---------|------|
| **SameSite Cookie** | `SESSION_COOKIE_SAMESITE="Lax"` 已配置，阻止跨站 Cookie 发送 |
| **CSRF Token** | 每个 session 生成唯一的 `secrets.token_hex(32)` token |
| **Token 校验** | `_validate_csrf()` 对比表单 token 与 session token |
| **密钥随机化** | `secrets.token_hex(32)` 确保 token 不可预测 |
| **Token 刷新机制** | 每次访问含 `csrf_token()` 的页面时自动刷新 token，缩短暴露窗口 |
| **Referer 辅助校验** | 可选：校验 `request.referrer` 是否来自本站 |

### CSRF Token 安全注意事项

> **Token 有效期**：当前 CSRF Token 在 session 中持久存在，每次调用 `csrf_token()` 渲染页面时刷新。如果 Token 被 XSS 窃取，攻击者可在同一 session 有效期内利用。每次 POST 成功后手动清除并刷新 Token 可进一步缩小攻击窗口。

> **Referer 头校验（辅助防御）**：
> ```python
> # 可选：在 _validate_csrf() 中添加
> if request.referrer and not request.referrer.startswith(request.host_url):
>     abort(403, "非法请求来源")
> ```
> 注意：Referer 头可能被浏览器隐私模式或代理移除，因此仅作为辅助手段，不能替代 CSRF Token。

> **CSRF + XSS 组合攻击风险**：如果系统存在 XSS 漏洞，攻击者可读取页面中的 `_csrf_token` 值，绕过 CSRF 保护直接发起合法请求。**CSRF 防护必须在无 XSS 漏洞的前提下才能完全生效。**

---

## 七、修复验证

### 测试结果

| 测试用例 | 结果 |
|---------|:----:|
| 不带 CSRF Token → 修改密码 | ❌ HTTP 403 — CSRF token 无效 ✅ |
| 带错误 CSRF Token → 修改密码 | ❌ HTTP 403 — CSRF token 无效 ✅ |
| 带正确 CSRF Token → 修改密码 | ✅ HTTP 302 — 重定向到个人中心 ✅ |
| 修改密码后 → 新密码登录 | ✅ HTTP 200 — 登录成功 ✅ |
| 外部恶意页面自动提交 | ❌ CSRF token 不匹配 → 拦截 ✅ |

### 其他已受 CSRF 保护的路由

| 路由 | 保护状态 |
|------|:--------:|
| `POST /login` | ✅ `_validate_csrf()` + 表单 token |
| `POST /register` | ✅ `_validate_csrf()` + 表单 token |
| `POST /upload` | ✅ `_validate_csrf()` + 表单 token |
| `POST /recharge` | ✅ `_validate_csrf()` + 表单 token |
| `POST /logout` | ✅ `_validate_csrf()` + 表单 token |
| `POST /change-password` | ✅ **现已修复** |

---

## 八、CSRF 防护总结

### 本应用的三层 CSRF 防御

```
第 1 层：SameSite Cookie 属性
└─ SESSION_COOKIE_SAMESITE="Lax"
   └─ 浏览器限制跨站请求携带 Cookie

第 2 层：CSRF Token 随机生成
└─ secrets.token_hex(32) → 64 字符十六进制字符串
   └─ 每个 session 独立，每次刷新页面自动更新

第 3 层：CSRF Token 严格校验
└─ _validate_csrf()
   └─ request.form["_csrf_token"] == session["_csrf_token"]
```

### 当前防御的局限性

| 局限性 | 说明 | 改进建议 |
|--------|------|---------|
| **无 HTTPS** | `SESSION_COOKIE_SECURE=False`，SameSite=Lax 在 HTTP 下部分浏览器行为不一致 | 生产环境启用 HTTPS + 设置 `SESSION_COOKIE_SECURE=True` |
| **SameSite 级别** | 当前为 `Lax`（仅阻止跨站 GET 携带 Cookie），`Strict` 级别保护更强 | 生产环境启用 `SESSION_COOKIE_SAMESITE="Strict"` |
| **Token 同源不可防** | CSRF Token 对同源 XSS 攻击无效（攻击者可读取页面 Token） | 必须配合 XSS 防护使用 |
| **Referer 未启用** | 当前未校验请求来源头 | 添加 Referer 校验作为辅助手段 |

### 修复前后对比

| 维度 | 修复前 | 修复后 |
|------|--------|--------|
| `/change-password` CSRF 保护 | ❌ 无 | ✅ 有 |
| 外部页面自动改密 | ✅ 可成功 | ❌ 被拦截 |
| 无 Token 请求 | ✅ 执行操作 | ❌ HTTP 403 |
| 错误 Token 请求 | ✅ 执行操作 | ❌ HTTP 403 |

### 全站 CSRF 防护覆盖率

```
修复前:  ████████████░░░░░░░░  60%  (5/6 路由受保护)
修复后:  ████████████████████ 100%  (6/6 路由受保护)
```

---

## 九、代码变更对比

```diff
--- a/app.py（修复前）
+++ b/app.py（修复后）

 @app.route("/change-password", methods=["POST"])
 def change_password():
-    """修改密码 — 不需要原密码、不需要 CSRF Token、不限目标用户"""
+    """修改密码 — 需要 CSRF Token 验证，防止跨站请求伪造"""
     if "username" not in session:
         return redirect(url_for("login"))
 
+    _validate_csrf()
+
     username = request.form.get("username")

--- a/templates/profile.html（修复前）
+++ b/templates/profile.html（修复后）

 <form method="post" action="/change-password" class="change-password-form">
+    <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
     <input type="hidden" name="username" value="{{ user.username }}">
```

---

## 十、全站安全总结（第七天）

### 项目累计漏洞全景

| 阶段 | 日期 | 功能 | 发现漏洞 | 已修复 |
|:----:|:----:|------|:-------:|:-----:|
| Day 1 | 7/8 | 初始审计 | 14 | 13 |
| Day 2 | 7/8 | 搜索 + 注册（SQL注入） | 5 | 0（教学保留） |
| Day 3 | 7/9 | 头像上传 | 4 | 3 |
| Day 5 | 7/9 | 个人中心 + 充值 | 7 | 0（教学保留） |
| Day 6 | 7/13 | 动态页面加载 | 2 | 2 |
| **Day 7** | **7/14** | **CSRF 修复** | **1** | **1** |
| | | **总计** | **33** | **19** |

### 当前遗留漏洞（教学保留）

| # | 漏洞 | 严重度 | 功能 |
|---|------|:------:|------|
| 1 | 搜索 SQL 注入 | 🔴 | /search |
| 2 | 注册 SQL 注入 | 🔴 | /register |
| 3 | SQL 日志泄露 | 🟡 | /search, /register |
| 4 | 注册输入无过滤 | 🟡 | /register |
| 5 | 搜索输入无过滤 | 🟡 | /search |
| 6 | 任意金额充值 | 🔴 | /recharge |
| 7 | 越权充值 | 🔴 | /recharge |
| 8 | 越权访问资料 | 🔴 | /profile |
| 9 | 金额无类型校验 | 🟠 | /recharge |
| 10 | 余额负数约束缺失 | 🟠 | /recharge |
| 11 | 无频率限制 | 🟡 | /recharge |
| 12 | User ID 可枚举 | 🟡 | /profile |
| 13 | 无文件类型校验 | 🟠 | /upload |

### 本日修复记录

| 漏洞 | 修复前 | 修复后 |
|------|--------|--------|
| `/change-password` 无 CSRF 防护 | ❌ 任意跨站请求均可修改密码 | ✅ CSRF Token 严格校验 |
| CSRF 防护覆盖率 | 60%（5/6 路由） | ✅ 100%（6/6 路由） |
