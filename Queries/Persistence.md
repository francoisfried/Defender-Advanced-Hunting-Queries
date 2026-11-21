# Persistence

## Notes:
- Each script includes a comment on which part should be customized, such as file hashes, IPs, or specific system directories, to suit your organization's environment.
- Ensure your query is designed to avoid false positives by fine-tuning based on local network behavior or naming conventions.

---

1. **Detect changes to registry run keys**
   ```kql
   // Adjust the registry key paths to match other areas of interest (e.g., software persistence locations)
   DeviceRegistryEvents
   | where ActionType in~ ("RegistryValueSet", "RegistryKeyCreated")
   | where RegistryKey endswith @"\CurrentVersion\Run" or RegistryKey endswith @"\CurrentVersion\RunOnce"
   | project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
   ```

2. **Identify new services**
   ```kql
   // Customize if attackers typically use different commands to create services
   DeviceProcessEvents
   | where FileName =~ "sc.exe" and ProcessCommandLine has "create"
   | project DeviceName, ProcessCommandLine, Timestamp
   ```

3. **Detect unusual scheduled tasks**
   ```kql
   // Modify the search to include other command-line tools for task scheduling (e.g., PowerShell)
   DeviceProcessEvents
   | where FileName =~ "schtasks.exe" and ProcessCommandLine contains "/create"
   | project DeviceName, ProcessCommandLine, Timestamp
   ```

4. **Detect auto-start entries in startup folders**
   ```kql
   // Adjust folder paths based on known or suspected locations attackers might use for persistence
   DeviceFileEvents
   | where ActionType == "FileCreated"
   | where FolderPath contains @"\Microsoft\Windows\Start Menu\Programs\Startup\"
   | project DeviceName, FileName, FolderPath, Timestamp
   ```

These are hunting leads, not proof of persistence. Review the affected value, task, service, or file and its creating process. Installers and administration tools commonly produce benign matches. The commands above do not cover every method of creating services or tasks.
