// Scenario (AI-generated):
// Detects executables with suspicious naming conventions such as starting with "agent_" or ending in "_loader.exe"
// Task: Write a rule to alert when such a file name is detected

rule suspicious_agent_or_loader_file {
    meta:
        author = "mt"
        description = "Detects agent or loader-style executable filenames"
    condition:
        file.name matches /^agent_/ or file.name matches /_loader\.exe$/
}
