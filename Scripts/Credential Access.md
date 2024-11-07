# Credential Access

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

2. **Detect possible credential dumping (LSASS access)**
   ```kql
   // Look for suspicious access to LSASS (commonly targeted for credential dumping)
   DeviceProcessEvents
   | where ProcessCommandLine contains "lsass.exe"
   | where InitiatingProcessCommandLine contains "procdump" or InitiatingProcessCommandLine contains "mimikatz"
   | project Timestamp, DeviceName, AccountName, InitiatingProcessCommandLine
   ```

3. **Detect suspicious use of `rundll32` for credential access**
   ```kql
   // Monitor for rundll32 being used suspiciously to invoke malicious DLLs for credential theft
   DeviceProcessEvents
   | where ProcessCommandLine contains "rundll32.exe"
   | where ProcessCommandLine contains "samcli.dll" or ProcessCommandLine contains "vaultcli.dll"  // DLLs related to credential theft
   | project Timestamp, DeviceName, AccountName, ProcessCommandLine
   ```

4. **Detect suspicious PowerShell use for credential theft**
   ```kql
   // Monitor for suspicious PowerShell commands that may be related to credential harvesting
   DeviceProcessEvents
   | where ProcessCommandLine contains "powershell.exe"
   | where ProcessCommandLine contains "Get-Credential" or ProcessCommandLine contains "Get-Clipboard"
   | project Timestamp, DeviceName, AccountName, ProcessCommandLine
   ```
