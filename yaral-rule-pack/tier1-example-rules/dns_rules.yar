// Scenario (AI-generated):
// Alert on DNS queries to .xyz or .top domains unless they start with cdn. or safe.
// Task: Write a rule to catch beaconing to suspicious domains while filtering known safe prefixes

rule dns_beaconing_filter_cdn_safe {
    meta:
        author = "mt"
        description = "Detects suspicious domain queries with safe prefix filtering"
    condition:
        dns.question.name matches /(\.xyz$|\.top$)/ and
        not (dns.question.name matches /^cdn\./ or dns.question.name matches /^safe\./)
}
