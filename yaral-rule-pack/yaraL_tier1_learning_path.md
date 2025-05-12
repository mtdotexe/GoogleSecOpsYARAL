# Tier 1 YARA-L Learning Path (Chronicle SecOps)

This document outlines my foundational journey in mastering detection engineering with YARA-L for Google Chronicle SecOps Soc tier 1 scope

---

## Phase 1: File-Based Detection

**Goal:** Match suspicious filenames and extensions  
**Field:** `file.name`  

**Skills:**
- `==` for exact file names (`"ransom.exe"`)
- `contains` for partials (`"patch"`)
- `matches` with regex: `/^agent_.*\.exe$/`

---

## Phase 2: DNS Domain Matching

**Goal:** Detect malicious domain queries  
**Field:** `dns.question.name`  

**Skills:**
- Match full domains (`==`)
- Regex for TLDs: `/\.xyz$/`, `/^login\./`
- Negation: `not dns.question.name matches /cdn/`

---

## Phase 3: URI Path Matching

**Goal:** Catch suspicious web requests  
**Field:** `http.request.uri`  

**Skills:**
- `contains "/update"`
- `matches` `/.*\.php$/`
- Regex with anchors and grouping

---

## Phase 4: User-Agent Analysis

**Goal:** Detect scripted or non-browser clients  
**Field:** `http.request.user_agent`  

**Skills:**
- Match suspicious tools: `curl`, `python`, `AutoUpdater`
- Regex patterns: `/^python/`, `/\/3\.1$/`
- Use `not` to exclude legit ones (`Mozilla`)

---

## Phase 5: IP Detection

**Goal:** Identify connections to malicious IPs  
**Field:** `network.connection.dst_ip`  

**Skills:**
- `==` match known malicious IPs
- Combine with file/UA logic

---

## Phase 6: Email-Based Detection

**Goal:** Spot suspicious emails and impersonation  
**Field:** `user.email`  

**Skills:**
- Match free email providers: `/@gmail\.com$/`
- Role-based names: `/^admin@/`, `/^support@/`
- Impersonation domains: `/micros0ft\.com$/`

---

## Phase 7: Hash and Hex Detection

**Goal:** Identify known malware samples  
**Fields:** `file.sha256`, `$hex`  

**Skills:**
- Match specific hashes
- Use byte signatures like `{ 55 8B EC 83 EC 10 }`

---

## Regex Training Phase

**Goal:** Master regex for all relevant fields  

**Fields Practiced:**  
- `file.name`, `http.request.uri`, `http.request.user_agent`, `dns.question.name`, `user.email`

**Skills:**
- Anchoring with `^` and `$`
- Grouping `()`, piping `|`
- Escaping: `\.`, `\/`
- Logic grouping in conditions

---

**Author:** `mtdotexe`  
**Scope:** SOC Tier 1 Detection Engineering  
**Platform:** Google Chronicle  

