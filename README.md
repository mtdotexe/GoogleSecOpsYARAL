# YARA-L Detection Rule Pack (Google Chronicle SOC Tiers 1 & 2)

This repository contains a full set of YARA-L detection rules created as part of a hands-on self-study project focused on building detection capability for Google Chronicle SecOps.

Each rule is grouped by log field and tier scope, aligned with SOC Analyst Tier 1 and Tier 2 responsibilities (possible tier 3 update soon).

---

## Folder Structure

```
yaral-rule-pack/
├── tier1-example-rules/
│   ├── file_name_rules.yar
│   ├── dns_rules.yar
│   ├── uri_rules.yar
│   ├── user_agent_rules.yar
│   ├── ip_rules.yar
│   ├── user_email_rules.yar
│   ├── hex_sha256_rules.yar
│   ├── final_challange.yar
│   ├── final_challange_obj.txt
│
├── tier2-example-rules/
│   ├── cloud_api_rules.yar
│   ├── multi_event_chain_rules.yar
│   ├── ioc_list_usage.yar
│   ├── timestamp_logic_rules.yar
│   ├── dns_hex_combo_rules.yar
│   ├── final_challange.yar
```

---

## Rule Notes

- Each `.yar` file includes:
  - A realistic **AI-generated detection scenario** (commented at the top)
  - A rule written by the analyst (me), using Chronicle YARA-L syntax
  - Fields are based on the [Chronicle Unified Data Model (UDM)](https://cloud.google.com/chronicle/docs/reference/udm-field-list)

---

## Tier 1 Coverage

| Log Field                     | Rule File                  | Techniques Used                    |
|------------------------------|----------------------------|------------------------------------|
| `file.name`                  | `file_name_rules.yar`      | Regex, suffix matching             |
| `dns.question.name`          | `dns_rules.yar`            | Regex, prefix & TLD filtering      |
| `http.request.uri`           | `uri_rules.yar`            | Contains, Regex, exclusion         |
| `http.request.user_agent`    | `user_agent_rules.yar`     | Regex anchors, exclusion grouping  |
| `network.connection.dst_ip`  | `ip_rules.yar`             | Direct IP match                    |
| `user.email`                 | `user_email_rules.yar`     | Regex, phishing pattern detection  |
| `file.sha256`, hex matching  | `hex_sha256_rules.yar`     | Hex + hash validation              |

---

## Tier 2 Coverage

| Feature/Field                | Rule File                     | Description                        |
|-----------------------------|-------------------------------|------------------------------------|
| API call usage              | `cloud_api_rules.yar`         | `api.call.name`, `service.account`|
| Chained events              | `multi_event_chain_rules.yar` | Login → drop correlation           |
| IOC list matching           | `ioc_list_usage.yar`          | UA IOC detection                   |
| Timing logic                | `timestamp_logic_rules.yar`   | Behavior chaining using timestamp  |
| DNS + hex combo             | `dns_hex_combo_rules.yar`     | Layered DNS + shellcode detection  |
| All techniques combined     | `final_challange.yar`         | Tier 2 "final boss" rule           |

---
## Tier 3 Coverage (in progress...)
---
## License

MIT License  
Rules authored by: **mt or aka mtdotexe**  
Scenarios generated and refined with the help of AI for learning and practice purposes.
