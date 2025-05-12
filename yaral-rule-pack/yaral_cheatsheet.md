# YARA-L Regex & Detection Logic Mega Cheat Sheet (Chronicle SecOps)

This cheat sheet captures everything I've learned about using regex and detection logic in YARA-L across Tier 1 and Tier 2 for Google Chronicle SecOps.

---

## ✅ Regex Pattern Anchors

- `^` → Start of string  
- `$` → End of string  
- `.*` → Match any number of characters  
- `[0-9]+` → One or more digits

---

## ✅ Rule of Thumb

- Use `^` and `$` to **anchor positions**
- Always **escape dots** (e.g., use `\.exe$` not `.exe$`)
- Wrap OR conditions in `(...)` or risk logic bugs
- `contains` ≠ `matches` — know when you're using regex vs string match

---

## ✅ Escape Characters to Remember

| Character | Escaped Form | Purpose |
|-----------|--------------|---------|
| `.`       | `\.`         | Match a literal dot (not any character) |
| `/`       | `\/`         | For paths like `/sync/init` |
| `+`       | `\+`         | Match literal plus or use `[0-9]+` |
| `?`       | `\?`         | Match literal question mark |
| `(`, `)`  | `\(`, `\)`  | Used in grouping or literal matches |

---

## ✅ Regex Logic Operators

| Symbol | Meaning              | Example                         |
|--------|----------------------|----------------------------------|
| `|`    | OR                   | `agent|loader`                  |
| `()`   | Group expressions    | `(agent|loader)\.exe$`         |
| `[]`   | Character classes    | `[0-9]` matches digits           |
| `.*`   | Match any characters | `/.*\.php$/`                   |

---

## ✅ Regex for Matching Types

| Use Case             | Regex Example                        |
|----------------------|---------------------------------------|
| Ends with `.exe`     | `/\.exe$/`                           |
| Starts with "admin"  | `/^admin/`                            |
| Contains "task"      | `/.*task.*/` or `contains "task"`     |
| File name + digits   | `/stage[0-9]+\.exe$/`                |
| UA ends with version | `/\/3\.1$/`                         |
| DNS TLDs             | `/\.xyz$|\.top$/`                   |

---

## ✅ Parentheses Logic Grouping

| Expression                 | Evaluates As                        |
|---------------------------|-------------------------------------|
| `a or b and c`            | `a or (b and c)` (default precedence) |
| `(a or b) and c`          | Forces correct group evaluation     |
| `not (a or b)`            | Use when excluding grouped matches  |

---

## ✅ `contains` vs `matches` vs `==`

| Operator   | Use Case                            | Regex?  |
|------------|-------------------------------------|---------|
| `==`       | Exact match                         | No      |
| `contains` | Substring (no regex)                | No      |
| `matches`  | Regular expression                  | Yes     |

---

## ✅ IOC List Matching: `any of ($ioc*) in ...`

**Example:**
```yaral
strings:
  $ioc1 = "curl"
  $ioc2 = "python"
  $ioc3 = "AutoSyncService"

condition:
  any of ($ioc*) in event3.http.request.user_agent
```

Use this technique when scanning fields for known tools or threats.

---

## ✅ Timestamp Logic (Chronicle Concept)

- **Timestamps are in milliseconds (ms)**  
- `1000 ms = 1 second`
- So:  
  - `30,000` ms = 30 seconds  
  - `60,000` ms = 1 minute  
  - `300,000` ms = 5 minutes

**Example:**
```yaral
event2.timestamp - event1.timestamp < 60000
```
Means the two events occurred within 1 minute of each other.

---

## ✅ Top Regex Things to Keep in Mind

- Always escape literal characters (dots, slashes, etc.)
- Use `^` + `$` when looking for start or end
- Use grouping when using ORs (`|`)
- Combine anchors and patterns carefully (e.g., `/^agent_.*\.exe$/`)
- Prefer `contains` for simple substring matches
- Validate `.yar` files in Google Chronicle before uploading

---

## ✅ Log Fields Covered + What They Mean

### Tier 1 Fields (Detection Engineering Basics)
- `file.name` → The name of a file observed in telemetry (e.g., `dropper.exe`)
- `dns.question.name` → The domain queried in DNS traffic (e.g., `example.com`)
- `http.request.uri` → The path and parameters in an HTTP request (e.g., `/login?user=admin`)
- `http.request.user_agent` → The user agent string in HTTP headers (e.g., `Mozilla/5.0`, `curl/7.68.0`)
- `network.connection.dst_ip` → The destination IP address a system connected to
- `user.email` → The email address of a user observed in a login or email activity
- `file.sha256` → The SHA-256 hash of a file
- `$hex` → A raw hex signature (malware shellcode or byte pattern)

### Tier 2 Fields (Cloud + Identity + Sequence Awareness)
- `event1.api.call.name` → The specific API function invoked (e.g., `drive.files.export`)
- `event1.service.account.name` → Name of the service account making the API call
- `event1.principal.email` → Email of the user or identity responsible for the API call
- `event2.file.name` → File involved in a later event (e.g., downloaded, modified)
- `event2.timestamp` → When event2 occurred (in milliseconds)
- `event3.timestamp` → When event3 occurred (used for timing logic)
- `event3.http.request.user_agent` → User agent string in the third event (e.g., data exfil)
- `event3.network.connection.dst_ip` → Destination IP contacted in event3
- `event3.dns.question.name` → DNS domain queried in event3


### Tier 1:
- `file.name`
- `dns.question.name`
- `http.request.uri`
- `http.request.user_agent`
- `network.connection.dst_ip`
- `user.email`
- `file.sha256`, `$hex`

### Tier 2 (Verified):
- `event1.api.call.name`
- `event1.service.account.name`
- `event1.principal.email`
- `event2.file.name`
- `event2.timestamp`
- `event3.timestamp`
- `event3.http.request.user_agent`
- `event3.network.connection.dst_ip`
- `event3.dns.question.name`

---

## ✅ Mistakes I went over 

- Forgetting to escape `.` and `/` in regex
- Using `|` without grouping → incorrect matches
- Mixing `contains` with regex without switching to `matches`
- Logic errors from bad OR/AND placement
- Forgetting timestamp gaps between chained events

---

## ✅ Challenges Faced & Lessons Learned

- Regex was initially confusing (especially escaping)
- Learned to properly group logical expressions
- Mastered event chaining with timestamp gaps
- Got better at clean rule structure and YAML-style formatting
- Learned how to validate and stage rules for Chronicle

---

## ✅ What I Can Do Now

- Write/read YARA-L rules; using regex, chaining, IOC lists
- Detect real-world attack behaviors in Google Chronicle
- Use logic like `matches`, `contains`, `not`, and `any of`
- Structure multi-event logic with `event1`, `event2`, etc.
- Build detection packs and document rules in GitHub

---

## ✅ What’s Next

- Begin **Tier 3**:
  - Behavioral modeling
  - Threat context correlation
  - External enrichment
- Operationalize rules in CI/CD or test environments
- Map to MITRE ATT&CK and build threat model sets

---

Written by: `mt aka mtdotexe` 