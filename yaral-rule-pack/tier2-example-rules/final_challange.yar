// Scenario (AI-generated):
// A threat actor uses a compromised service account to invoke the Google Drive API 
// to access and exfiltrate sensitive files. The dropper file is named using a 
// pattern such as data_sync#.exe or data_dump#.exe. The access and exfiltration 
// steps happen in rapid sequence (within 60 seconds). The user agent mimics tools 
// like curl, python, or a custom script, and the DNS query targets suspicious TLDs 
// like .xyz or .top while avoiding known safe infrastructures like cdn., proxy., etc.
// The rule also validates the presence of a known shellcode pattern during this chain.

rule tier2_final_boss_challenge {
    meta:
        author = "mt"
        description = "Tier 2 boss rule combining API, identity, file, UA, IP, DNS, and hex matching"

    strings:
        $ua1 = "curl"
        $ua2 = "python"
        $ua3 = "AutoDump/4.1"
        $hex = { 60 BE ?? ?? ?? ?? 8B 06 FF 50 08 }

    condition:
        event1.service.account.name contains "bot" and
        event1.api.call.name == "drive.files.export" and
        event2.file.name matches /^data_(sync|dump)[0-9]+\.exe$/ and
        event2.timestamp - event1.timestamp < 60000 and
        event3.timestamp - event2.timestamp < 60000 and
        any of ($ua*) in event3.http.request.user_agent and
        (
            event3.dns.question.name matches /\.xyz$|\.top$/ and
            not event3.dns.question.name matches /^(cdn\.|proxy\.|safe\.)/
        ) and
        $hex
}
