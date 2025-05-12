// Scenario (AI-generated):
// Detect tightly timed activity across multiple steps (download > execution > beacon)
// Task: Apply timestamp logic to spot fast attack sequences

rule chained_file_exec_within_60s {
    meta:
        author = "mt"
        description = "Detects tight behavior chaining across events"
    condition:
        event2.timestamp - event1.timestamp < 60000 and
        event3.timestamp - event2.timestamp < 60000
}
