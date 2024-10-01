# Defense Evasion

## Notes:
- Each script includes a comment on which part should be customized, such as file hashes, IPs, or specific system directories, to suit your organization's environment.
- Ensure your query is designed to avoid false positives by fine-tuning based on local network behavior or naming conventions.

---

1. **Detect suspicious WMI activity**
   ```kql
   // Modify if specific WMI commands are of interest (e.g., suspicious processes)
   DeviceProcessEvents
   | where ProcessCommandLine contains "wmic"
   | project DeviceName, ProcessCommandLine, Timestamp
   ```

2. **Identify unsigned executables running from system folders**
   ```kql
   // Adjust folder paths to include other system folders if applicable in your environment
   DeviceFileEvents
   | where FolderPath contains "C:\\Windows" and FileName endswith ".exe"
   | where isnotempty(Signer) == false
   | project DeviceName, FileName, FolderPath, Timestamp
   ```
