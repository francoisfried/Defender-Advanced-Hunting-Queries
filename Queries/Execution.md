# Execution

## Notes:
- Each script includes a comment on which part should be customized, such as file hashes, IPs, or specific system directories, to suit your organization's environment.
- Ensure your query is designed to avoid false positives by fine-tuning based on local network behavior or naming conventions.

---

1. **Detect files with known malware hashes**
   ```kql
   // Edit the list of known bad hashes to match the malware you are searching for
   DeviceFileEvents
   | where SHA256 in ("known_hash_1", "known_hash_2", "known_hash_3")
   | project DeviceName, SHA256, FileName, FolderPath, Timestamp
   ```

2. **Detect unusual file executions**
   ```kql
   // Customize "Temp" and "AppData" if malware is known to execute from other directories
   DeviceProcessEvents
   | where ProcessCommandLine contains ".exe" and (InitiatingProcessFolderPath contains "Temp" or InitiatingProcessFolderPath contains "AppData")
   | project DeviceName, ProcessCommandLine, InitiatingProcessFolderPath, Timestamp
   ```

3. **Identify PowerShell script executions**
   ```kql
   // Add specific PowerShell commands you expect attackers to use, if known
   DeviceProcessEvents
   | where ProcessCommandLine contains "powershell"
   | project DeviceName, ProcessCommandLine, Timestamp
   ```

4. **Detect suspicious WMI activity**
   ```kql
   // Modify if specific WMI commands are of interest (e.g., suspicious processes)
   DeviceProcessEvents
   | where ProcessCommandLine contains "wmic"
   | project DeviceName, ProcessCommandLine, Timestamp
   ```
