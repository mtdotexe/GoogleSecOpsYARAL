// Scenario (AI-generated):
// Detects usage of sensitive Google Drive API calls by service accounts (e.g. bots)
// Task: Alert on 'drive.files.download' or 'drive.files.export' activity by non-human accounts

rule service_account_file_api_access {
    meta:
        author = "mt"
        description = "Detects service accounts accessing sensitive cloud file APIs"
    condition:
        event1.service.account.name contains "bot" and
        (
            event1.api.call.name == "drive.files.download" or
            event1.api.call.name == "drive.files.export"
        )
}
