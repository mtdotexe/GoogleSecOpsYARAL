// Scenario:
// Final Boss - Full Tier 1 scope challenge 
// Detects staged malware delivery via suspicious file names, phishing email senders,
// beaconing HTTP URIs and evasive UAs, suspicious IPs and DNS queries, along with
// known hex and SHA256 hash indicators.

rule complex_staged_malware {
    meta:
        author = "mt"
        description = "Ultimate Tier 1 detection rule covering all Chronicle fields and techniques learning purposes only"

    strings:
        $hex = { 60 BE ?? ?? ?? ?? 8B 06 FF 50 08 }
        $sha256 = "e99a18c428cb38d5f260853678922e03abd8335c8490d7317d6d7f2342a33bc4"

    condition:
        (
            file.name matches /^agent_.*$/ or
            file.name matches /(\.injector\.exe|\.dropper\.exe|\.stage1\.exe)$/
        )
        and
        (
            http.request.uri matches /(\.php$|\.exe$)/ and
            (http.request.uri contains "/sync" or http.request.uri contains "/task") and
            not (http.request.uri contains "/safe" or http.request.uri contains "/test")
        )
        and
        (
            http.request.user_agent matches /^python/ or
            http.request.user_agent matches /^AutoFetcher/ or
            http.request.user_agent matches /\/3\.1$/
        )
        and not (
            http.request.user_agent matches /Mozilla/ or
            http.request.user_agent matches /Chrome/ or
            http.request.user_agent matches /Edge/
        )
        and
        (
            dns.question.name matches /(\.xyz$|\.top$|\.info$)/ and
            not (
                dns.question.name matches /^cdn\./ or
                dns.question.name matches /^static\./ or
                dns.question.name matches /^safe\./
            )
        )
        and
        (
            network.connection.dst_ip == "203.0.113.11" or
            network.connection.dst_ip == "198.51.100.7"
        )
        and
        (
            user.email matches /^admin@/ or
            user.email matches /^support@/ or
            user.email matches /@protonmail\.com$/ or
            user.email matches /@secure-mail\.org$/
        )
        and file.sha256 == $sha256
        and $hex
}
