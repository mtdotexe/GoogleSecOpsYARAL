// Scenario (AI-generated):
// Alert if a file hash matches known malware or contains known shellcode
// Task: Combine SHA256 and hex matching in one rule

rule hash_and_shellcode_validation {
    meta:
        author = "mt"
        description = "Matches known malware hash and hex signature"
    strings:
        $hex = { 6A 40 68 00 30 00 00 }
        $sha256 = "e99a18c428cb38d5f260853678922e03abd8335c8490d7317d6d7f2342a33bc4"
    condition:
        file.sha256 == $sha256 and $hex
}
