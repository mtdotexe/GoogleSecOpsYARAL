// Scenario (AI-generated):
// Catch DNS queries to suspicious domains that also match hex patterns
// Task: Use regex and shellcode matching to alert on exfil behavior

rule dns_and_shellcode_combo {
    meta:
        author = "mt"
        description = "Alerts on DNS to suspicious TLDs with known shellcode present"
    strings:
        $hex = { 55 8B EC 83 EC 10 }
    condition:
        event3.dns.question.name matches /\.xyz$/ and
        not event3.dns.question.name matches /^cdn\./ and
        $hex
}
