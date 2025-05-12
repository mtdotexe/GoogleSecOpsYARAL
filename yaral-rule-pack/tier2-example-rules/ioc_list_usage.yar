// Scenario (AI-generated):
// Match user-agents against a known list of malicious tools or scrapers
// Task: Use 'any of ($ua*) in ...' to catch common attacker toolkits

rule malicious_user_agent_list_match {
    meta:
        author = "mt"
        description = "Matches common attacker tools using IOC list"
    strings:
        $ua1 = "curl"
        $ua2 = "python"
        $ua3 = "AutoSyncService/9.9"
    condition:
        any of ($ua*) in event2.http.request.user_agent
}
