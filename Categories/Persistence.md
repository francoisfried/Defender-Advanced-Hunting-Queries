# Persistence

## Notes:
- Each script includes a comment on which part should be customized, such as file hashes, IPs, or specific system directories, to suit your organization's environment.
- Ensure your query is designed to avoid false positives by fine-tuning based on local network behavior or naming conventions.

---

1. **Detect changes to registry run keys**
   ```kql
   // Adjust the registry key paths to match other areas of interest (e.g., software persistence locations)
   DeviceRegistryEvents
   | where RegistryKeyPath endswith "Run"
   | project DeviceName, RegistryKeyPath, RegistryValueName, Timestamp
   ```

2. **Identify new services**
   ```kql
   // Customize if attackers typically use different commands to create services
   DeviceProcessEvents
   | where ProcessCommandLine contains "sc.exe create"
   | project DeviceName, ProcessCommandLine, Timestamp
   ```

3. **Detect unusual scheduled tasks**
   ```kql
   // Modify the search to include other command-line tools for task scheduling (e.g., PowerShell)
   DeviceProcessEvents
   | where ProcessCommandLine contains "schtasks"
   | project DeviceName, ProcessCommandLine, Timestamp
   ```

4. **Detect auto-start entries in startup folders**
   ```kql
   // Adjust folder paths based on known or suspected locations attackers might use for persistence
   DeviceFileEvents
   | where FolderPath contains "Startup"
   | project DeviceName, FileName, FolderPath, Timestamp
   ```

5. **Detect DLL hijacking attempts**
   ```kql
   // Modify file paths and file types if you suspect DLL hijacking attempts in other directories
   DeviceFileEvents
   | where FileName endswith ".dll" and (FolderPath contains "Windows" or FolderPath contains "System32")
   | project DeviceName, FileName, FolderPath, Timestamp
   ```
