# Tier 3 YARA-L Learning Path (Chronicle SecOps – Advanced SOC Scope)

This roadmap outlines the planned progression for mastering Tier 3 detection engineering using YARA-L in Google Chronicle. Focus areas include behavioral modeling, threat correlation, and enriched context analysis.

---

## Phase 1: Behavioral & Threat Context Correlation

**Objective:** Learn to build rules using detection context, behavior categories, and severity ratings.

**Planned Fields:**
- `security_result.detection_names`
- `security_result.category`
- `security_result.severity`

**Learning Goals:**
- Trigger alerts based on prior detection names (e.g., `"Credential Access"`)
- Integrate behavior classification and severity into rule logic
- Refine prioritization through context-aware logic

---

## Phase 2: Asset & Resource Attribution

**Objective:** Understand how to detect attacks targeting cloud workloads and key infrastructure assets.

**Planned Fields:**
- `target.resource.name`
- `target.resource.project_id`

**Learning Goals:**
- Match assets by name (e.g., `contains "prod-vm"`)
- Monitor activity scoped to specific project IDs
- Identify attacks on sensitive systems

---

## Phase 3: Geographic & Location-Based Analysis

**Objective:** Learn how to detect geographic anomalies and policy violations using location metadata.

**Planned Fields:**
- `principal.location.region_code`
- `principal.ip`

**Learning Goals:**
- Match risky regions or exclude trusted locations
- Flag logins or activity from unusual IP addresses
- Pair geo signals with behavior or identity

---

## Phase 4: Identity Access & Misuse

**Objective:** Detect identity-based threats including account impersonation and lateral movement.

**Planned Fields:**
- `principal.resource.name`
- `principal.hostname`
- `principal.authentication_info.credential_id`
- `actor.user.group`

**Learning Goals:**
- Match suspicious credential usage patterns
- Detect shared hostnames across multiple identities
- Analyze group or role-based escalation behavior

---

## Phase 5: Threat Intelligence Matching (Optional)

**Objective:** Gain exposure to matching against threat indicators from external intel feeds.

**Planned Fields:**
- `threat.indicator.type`
- `threat.indicator.value`
- `threat.indicator.confidence`

**Learning Goals:**
- Build rules that trigger on enriched IoCs
- Filter using confidence levels
- Detect known threat infrastructure in context

---

## Phase 6: SaaS / Cloud-Specific Activities

**Objective:** Monitor cloud-native behavior in (eg.Google Workspace, Okta, Azuer AD, etc) or SaaS activity logs.

**Planned Fields:**
- `activity.name`
- `device.resource.name`
- `access.approval.name`

**Learning Goals:**
- Detect actions like `token refresh`, `access denied`, or new `device approvals`
- Chain SaaS actions to identity or credential misuse

---

## Tier 3 Final Challange (Capstone)

**Objective:** Design a high-fidelity, multi-event rule combining behavior, identity, geography, and threat indicators.

**Expected Rule Components:**
- Detection names + severity + geo + identity + cloud resource
- Multi-event chaining across `event1`, `event2`, `event3`
- Use of regex, logic grouping, negation, `any of`, and IOC list matching

---

**Author:** mt  
**Scope:** Tier 3 SOC Analyst / Detection Engineer (Planned Study Path)  
**Platform:** Google Chronicle  
