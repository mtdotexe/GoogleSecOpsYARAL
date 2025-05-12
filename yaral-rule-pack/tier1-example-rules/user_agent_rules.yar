// Scenario (AI-generated):
// Alert if the user-agent string starts with curl or ends with /2.1, but not if it contains 'Mozilla'
// Task: Detect scripted UAs and evade browser traffic

rule suspicious_user_agents_not_browser {
    meta:
        author = "mt"
        description = "Detects curl or /2.1 user-agents, excluding Mozilla"
    condition:
        (
            http.request.user_agent matches /^curl/ or
            http.request.user_agent matches /\/2\.1$/
        )
        and not http.request.user_agent matches /Mozilla/
}
