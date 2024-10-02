# Discovery

## Notes:
- Each script includes a comment on which part should be customized, such as file hashes, IPs, or specific system directories, to suit your organization's environment.
- Ensure your query is designed to avoid false positives by fine-tuning based on local network behavior or naming conventions.

---

1. **Identify multiple failed network logon attempts**
   ```kql
   // Customize threshold (e.g., >5) for login failures based on your security policy
   DeviceNetworkEvents
   | where ActionType == "FailedLogin"
   | summarize FailedAttempts = count(), LastAttempt = max(Timestamp) by InitiatingProcessAccountName, RemoteIP
   | where FailedAttempts > 5
   | project LastAttempt, InitiatingProcessAccountName, RemoteIP, FailedAttempts
   ```

2. **Detect network scanning activity**
   ```kql
   // Replace RemotePort values to target additional known scanning ports or services
   DeviceNetworkEvents
   | where ActionType == "Scan" and RemotePort < 1024
   | summarize count() by DeviceName, RemoteIP
   ```
