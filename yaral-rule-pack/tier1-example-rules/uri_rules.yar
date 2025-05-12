// Scenario (AI-generated):
// Match HTTP paths containing '/sync' or ending in '.php', excluding those with '/safe'
// Task: Write a rule to detect command and control traffic with URI path filtering

rule http_sync_or_php_not_safe {
    meta:
        author = "mt"
        description = "Detects URIs matching sync or php patterns excluding /safe"
    condition:
        (http.request.uri contains "/sync" or http.request.uri matches /\.php$/) and
        not http.request.uri contains "/safe"
}
