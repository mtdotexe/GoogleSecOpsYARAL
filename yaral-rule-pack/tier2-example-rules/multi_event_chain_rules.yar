// Scenario (AI-generated):
// Sequence detection of admin login followed by file drop
// Task: Correlate a suspicious login to a staged payload drop using multiple events

rule admin_login_then_payload {
    meta:
        author = "mt"
        description = "Correlates admin login followed by payload delivery"
    condition:
        event1.principal.email contains "admin@" and
        event2.file.name matches /^payload_.*\.exe$/
}
