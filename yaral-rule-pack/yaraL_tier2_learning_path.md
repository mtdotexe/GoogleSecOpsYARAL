# Tier 2 YARA-L Learning Path (Chronicle SecOps)

This document outlines the full Tier 2 learning journey I completed to master advanced detection techniques in Google Chronicle SecOps using YARA-L.

---

## Phase 1: Identity + Cloud API Correlation

**Goal:** Detect cloud abuse by linking identities to suspicious API actions

**Fields Covered:**
- `event1.principal.email`
- `event1.api.call.name`
- `event1.service.account.name`

**Skills Learned:**
- Match admin/role-based identities
- Detect risky API calls (e.g. `drive.files.download`)
- Combine account identity + API logic

---

## Phase 2: File Drop + Chaining + Timing Logic

**Goal:** Track malicious file usage tied to cloud/download events

**Fields Covered:**
- `event2.file.name`
- `event2.timestamp`
- `event3.timestamp`

**Skills Learned:**
- Regex on file drops: `/payload_[0-9]+\.exe$/`
- Chain file event to previous API action
- Use timing logic: `event2.timestamp - event1.timestamp < 60000`

---

## Phase 3: HTTP + User-Agent Threat Indicators

**Goal:** Detect suspicious tooling (curl, python, custom scripts)

**Fields Covered:**
- `event3.http.request.user_agent`

**Skills Learned:**
- Detect tools with regex (`/^python/`, `/\/3\.1$/`)
- Use IOC lists: `any of ($ioc*) in ...`
- Use `not user_agent contains "Mozilla"` to avoid legit browser noise

---

## Phase 4: Network + DNS Threat Correlation

**Goal:** Catch C2 infrastructure, DNS beacons, or exfil attempts

**Fields Covered:**
- `event3.network.connection.dst_ip`
- `event3.dns.question.name`

**Skills Learned:**
- Match C2 IPs
- Match domains with suspicious TLDs: `.xyz`, `.top`
- Use negated DNS logic: `not dns.question.name matches /^cdn\./`

---

**Author:** `mtdotexe`  
**Scope:** SOC Tier 2 Detection Engineering  
**Platform:** Google Chronicle  
**Format:** Markdown `.md`  
