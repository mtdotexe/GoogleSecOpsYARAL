// Scenario (AI-generated):
// Detect outbound connections to known C2 IPs
// Task: Write a rule to match specific IP destinations

rule detect_known_c2_ip {
    meta:
        author = "mt"
        description = "Detects connection to known C2 address"
    condition:
        network.connection.dst_ip == "198.51.100.7"
}
