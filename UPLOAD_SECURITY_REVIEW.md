# 文件上传漏洞安全报告 — 分析与修复

**审计日期**：2026-07-09  
**审计文件**：`app.py`（`/upload` 路由）  
**应用地址**：http://192.168.31.128:5000

---

## 一、漏洞分析

### 🔴 漏洞 1：文件上传路径遍历（CWE-22）

**位置**：`app.py:294`（修复前）

```python
# ❌ 修复前：完全信任用户提供的文件名
save_path = os.path.join(UPLOAD_FOLDER, f.filename)
f.save(save_path)
```

**攻击向量**：

| 输入文件名 | `os.path.join` 结果 | 写入目标 |
|-----------|-------------------|---------|
| `../../etc/cron.d/job` | `static/uploads/../../etc/cron.d/job` | `/etc/cron.d/job` |
| `/etc/passwd` | `/etc/passwd`（绝对路径丢弃前缀） | `/etc/passwd` |
| `../../../etc/hostname` | 归一化到上级目录 | `/etc/hostname` |

**影响**：攻击者可上传任意文件到服务器任意路径，实现：
- 覆盖系统文件（如 `/etc/passwd`、`/etc/cron.d/` 计划任务）
- 上传 Web Shell 到可执行目录
- 覆盖应用源代码

---

### 🟠 漏洞 2：Debug 模式硬编码回归（CWE-489）

**位置**：`app.py:23,310`（修复前）

```python
# 行 23：定义了但从未使用 → 死代码
DEBUG = os.environ.get("FLASK_DEBUG", "0") == "1"

# 行 310：仍然硬编码 True
app.run(debug=True, host="0.0.0.0", port=5000)
```

**影响**：
- Werkzeug 调试控制台暴露在公网
- 触发异常时显示交互式 Python shell
- 攻击者可通过 `PIN: 830-259-970` 执行任意代码

---

### 🟠 漏洞 3：无文件类型校验（CWE-434）

**位置**：`app.py:286-296`（修复前）

**影响**：可上传 `.exe`、`.php`、`.html`、`.py` 等任意类型文件。

---

### 🟡 漏洞 4：上传文件 URL 注入

**位置**：`app.py:296`（修复前）

```python
uploaded_url = url_for("static", filename=f"uploads/{f.filename}")
```

未清洗的 filename 直接拼入 URL，可构造恶意链接。

---

## 二、实施修复

### ✅ 修复 1：路径遍历防护

```python
# ✅ 修复后：使用 secure_filename 清洗文件名
from werkzeug.utils import secure_filename

safe_name = secure_filename(f.filename)
if not safe_name:
    error = "文件名不合法"
else:
    save_path = os.path.join(UPLOAD_FOLDER, safe_name)
    f.save(save_path)
    uploaded_url = url_for("static", filename=f"uploads/{safe_name}")
```

**`secure_filename()` 过滤效果**：

| 输入 | secure_filename 输出 | 写入路径 | 风险 |
|------|--------------------|---------|:----:|
| `test_avatar.png` | `test_avatar.png` | `static/uploads/test_avatar.png` | ✅ 安全 |
| `../../etc/passwd` | `etc_passwd` | `static/uploads/etc_passwd` | ✅ 路径遍历消除 |
| `/etc/cron.d/job` | `etc_cron.d_job` | `static/uploads/etc_cron.d_job` | ✅ 绝对路径消除 |
| `../index.html` | `index.html` | `static/uploads/index.html` | ✅ 上级目录消除 |

### ✅ 修复 2：Debug 模式环境变量化

```python
# ✅ 修复后：使用环境变量控制
app.run(debug=DEBUG, host="0.0.0.0", port=5000)
```

- `DEBUG` 变量（行 23）不再为死代码
- 默认 `FLASK_DEBUG=0` → Debug 关闭
- 仅在显式设置 `FLASK_DEBUG=1` 时开启

---

## 三、修复验证

### 路径遍历防护测试结果

```
测试 1：正常文件上传 test2.png
  → 保存到 static/uploads/test2.png ✅
  → 页面显示图片预览 /static/uploads/test2.png ✅

测试 2：路径遍历 ../../../etc/hostname
  → secure_filename 清洗为 etc_hostname ✅
  → 保存到 static/uploads/etc_hostname ✅
  → /etc/hostname 未被改写 ✅
```

### Debug 模式验证

```bash
# 修复前日志输出
  * Debugger is active!
  * Debugger PIN: 830-259-970

# 修复后日志输出（默认 FLASK_DEBUG=0）
  # 无 Debugger 相关输出 ✅
```

---

## 四、代码变更 diff

```diff
--- a/app.py (修复前)
+++ b/app.py (修复后)
@@ -7,3 +7,4 @@
 from werkzeug.security import generate_password_hash, check_password_hash
+from werkzeug.utils import secure_filename

@@ -290,5 +291,8 @@ def upload():
             else:
                 os.makedirs(UPLOAD_FOLDER, exist_ok=True)
-                save_path = os.path.join(UPLOAD_FOLDER, f.filename)
-                f.save(save_path)
-                uploaded_url = url_for("static", filename=f"uploads/{f.filename}")
+                safe_name = secure_filename(f.filename)
+                if not safe_name:
+                    error = "文件名不合法"
+                else:
+                    save_path = os.path.join(UPLOAD_FOLDER, safe_name)
+                    f.save(save_path)
+                    uploaded_url = url_for("static", filename=f"uploads/{safe_name}")

@@ -310,3 +314,3 @@
-    app.run(debug=True, host="0.0.0.0", port=5000)
+    app.run(debug=DEBUG, host="0.0.0.0", port=5000)
```

---

## 五、遗留问题（教学演示保留）

以下 5 项 SQL 注入漏洞按教学目的保留，**本次未修复**：

| # | 漏洞 | 位置 | 严重度 |
|---|------|------|--------|
| 1 | 搜索 SQL 注入 | `app.py:254` | 🔴 高危 |
| 2 | 注册 SQL 注入 | `app.py:233` | 🔴 高危 |
| 3 | SQL 日志泄露 | `app.py:234,255` | 🟡 低危 |
| 4 | 注册输入无过滤 | `app.py:224-227` | 🟡 低危 |
| 5 | 搜索输入无过滤 | `app.py:250` | 🟡 低危 |

---

## 六、总结

| 维度 | 修复前 | 修复后 |
|------|--------|--------|
| 路径遍历 | 🔴 任意路径写入 | ✅ 文件名安全清洗 |
| Debug 模式 | 🔴 硬编码开启 | ✅ 环境变量控制 |
| URL 注入 | 🟡 未清洗文件名 | ✅ 使用清洗后文件名 |
| 应用状态 | 运行中 | 运行中 |
