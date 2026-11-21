# Exfiltration

## Notes:
- Each script includes a comment on which part should be customized, such as file hashes, IPs, or specific system directories, to suit your organization's environment.
- Ensure your query is designed to avoid false positives by fine-tuning based on local network behavior or naming conventions.

---

1. **Frequent DNS destination activity**
   ```kql
   // A network event on port 53 does not necessarily include the requested DNS name.
   DeviceNetworkEvents
   | where RemotePort == 53 and isnotempty(RemoteIP)
   | summarize ConnectionCount = count() by DeviceName, RemoteIP, bin(Timestamp, 1h)
   | where ConnectionCount > 100
   ```

2. **Exfiltration Over C2 Channel**

```kql
// Detect unusual outbound connections to external IPs by uncommon processes
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName != "System"  // Exclude system processes; add more if necessary
| where isnotempty(RemoteIP) and ipv4_is_private(RemoteIP) == false
| where RemoteIP !in ("127.0.0.1", "0.0.0.0")
| summarize ConnectionCount = count() by
    DeviceName, 
    InitiatingProcessFileName, 
    InitiatingProcessCommandLine, 
    RemoteIP
| where ConnectionCount > 1000  // Adjust this threshold based on normal activity
| order by ConnectionCount desc
```

`DeviceNetworkEvents` does not establish HTTP method or bytes uploaded. Correlate these connections with proxy or firewall logs before treating them as exfiltration. The public IP filter above covers IPv4; review IPv6 separately.

3. **Exfiltration Over Web Service**

This query looks for repeated connections to selected cloud storage services. Connections alone do not establish uploads.

```kql
// Find repeated connections to cloud storage services
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess" and isnotempty(RemoteUrl)
| where InitiatingProcessFileName != "System"  // Exclude system processes; modify as needed
| where RemoteUrl contains "dropbox.com" or RemoteUrl contains "drive.google.com"
    or RemoteUrl contains "onedrive.live.com" or RemoteUrl contains "box.com"
| summarize ConnectionCount = count() by
    DeviceName, 
    InitiatingProcessFileName, 
    InitiatingProcessCommandLine, 
    RemoteUrl
| where ConnectionCount > 50  // Adjust based on typical usage in your organization
| order by ConnectionCount desc
```

4. **Archive Collected Data**

This query detects the creation of archive files by unusual processes, which may signal data being prepared for exfiltration.

```kql
// Detect creation of archive files by unusual processes
DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName endswith '.zip' or FileName endswith '.rar' or FileName endswith '.7z' or FileName endswith '.tar.gz'
// Add or remove file extensions above to match archive formats used in your environment
| project Timestamp, 
    DeviceName, 
    InitiatingProcessFileName, 
    InitiatingProcessCommandLine, 
    FolderPath, 
    FileName
| order by Timestamp desc
```

Archive creation is a staging lead, not proof of exfiltration. Review the archive contents and subsequent network activity. Backups and packaging are common benign causes.
