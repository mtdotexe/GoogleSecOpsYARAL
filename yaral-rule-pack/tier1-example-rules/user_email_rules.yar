// Scenario (AI-generated):
// Detect impersonated role-based emails or fake domains
// Task: Write a rule that matches suspicious sender patterns

rule impersonation_email_detection {
    meta:
        author = "mt"
        description = "Detects role-based phishing emails or typosquatted domains"
    condition:
        user.email matches /^admin@/ or
        user.email matches /^support@/ or
        user.email matches /micros0ft\.com$/ or
        user.email matches /paypa1\.com$/
}
