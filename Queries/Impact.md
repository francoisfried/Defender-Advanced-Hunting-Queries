# Impact

## Notes:
- Each script includes a comment on which part should be customized, such as file hashes, IPs, or specific system directories, to suit your organization's environment.
- Ensure your query is designed to avoid false positives by fine-tuning based on local network behavior or naming conventions.

---

1. **Data Encrypted for Impact**

This query detects processes that are encrypting multiple files, which may indicate ransomware activity.

```kql
// Detect potential ransomware file encryption activity
DeviceFileEvents
| where ActionType == "FileModified"
| where FileName endswith ".encrypted" or FileName matches regex @".*\.(lock|crypt|cry)$"
    // Add or modify file extensions and patterns relevant to known ransomware in your environment
| where InitiatingProcessFileName != "explorer.exe"  // Exclude legitimate processes; add more if necessary
| summarize FileCount = count() by DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine
| where FileCount > 100  // Adjust threshold based on normal activity
| order by FileCount desc
```

2. **Inhibit System Recovery**

This query identifies attempts to delete or modify system recovery configurations or shadow copies, which can inhibit system recovery.

```kql
// Detect deletion of shadow copies and modifications to system recovery settings
DeviceProcessEvents
| where ProcessCommandLine has_any ("vssadmin delete shadows", "wmic shadowcopy delete", "diskshadow")
    or ProcessCommandLine has_any ("bcdedit /set", "wbadmin delete", "Remove-Item")
    // Add or adjust commands based on methods used to inhibit system recovery
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

3. **Service Stop**

This query detects attempts to stop or disable services, which can impact system functionality or security.

```kql
// Detect attempts to stop or disable services
DeviceProcessEvents
| where ProcessCommandLine has_any ("net stop", "sc stop", "Set-Service -Status Stopped", "Stop-Service")
    // Modify the list above to include other commands used to stop services
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

4. **System Shutdown/Reboot**

This query identifies processes initiating a system shutdown or reboot, which could be malicious if unexpected.

```kql
// Detect processes initiating system shutdown or reboot
DeviceProcessEvents
| where ProcessCommandLine has_any ("shutdown /s", "shutdown /r", "Restart-Computer", "Stop-Computer")
    // Add other commands or scripts used to shutdown or reboot systems in your environment
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

5. **Defacement**

This query detects modifications to web server content directories, which may indicate defacement activities.

```kql
// Detect modifications to web server content directories
DeviceFileEvents
| where ActionType in ("FileCreated", "FileModified", "FileDeleted")
| where FolderPath startswith @"C:\inetpub\wwwroot" or FolderPath startswith @"/var/www/html"
    // Adjust the paths above to match web content directories in your environment
| where InitiatingProcessFileName !in~ ("w3wp.exe", "httpd.exe", "nginx.exe")
    // Exclude legitimate web server processes; add more if necessary
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```
