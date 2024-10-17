# Exfiltration

## Notes:
- Each script includes a comment on which part should be customized, such as file hashes, IPs, or specific system directories, to suit your organization's environment.
- Ensure your query is designed to avoid false positives by fine-tuning based on local network behavior or naming conventions.

---

1. **Unusual DNS requests**
   ```kql
   // Adjust RemotePort if looking at different DNS services; customize domain TLDs if necessary
   DeviceNetworkEvents
   | where RemotePort == 53 and not (RemoteIP contains ".com" or RemoteIP contains ".org")
   | project DeviceName, RemoteIP, Timestamp
   ```

2. **Exfiltration Over C2 Channel**

```kql
// Detect unusual outbound connections to external IPs by uncommon processes
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName != "System"  // Exclude system processes; add more if necessary
| where RemoteIPType == "Public"  // Filters for external IP addresses
| summarize ConnectionCount = count() by 
    DeviceName, 
    InitiatingProcessFileName, 
    InitiatingProcessCommandLine, 
    RemoteIP
| where ConnectionCount > 1000  // Adjust this threshold based on normal activity
| order by ConnectionCount desc
```

```kql
// Detect processes making a high number of HTTP POST requests to external IPs
DeviceNetworkEvents
| where ActionType == "HttpPost"
| where RemoteIPType == "Public"
| where InitiatingProcessFileName != "System"
| summarize PostCount = count() by 
    DeviceName, 
    InitiatingProcessFileName, 
    InitiatingProcessCommandLine, 
    RemoteIP, 
    RemoteUrl
| where PostCount > 100  // Adjust this threshold based on normal activity
| order by PostCount desc
```

3. **Exfiltration Over Web Service**

This query looks for HTTP POST requests to popular cloud storage services, which may indicate data exfiltration via web services.

```kql
// Detect high number of HTTP POST requests to cloud storage services
DeviceNetworkEvents
| where ActionType == "HttpPost"
| where InitiatingProcessFileName != "System"  // Exclude system processes; modify as needed
| where RemoteUrl matches regex @"(dropbox\.com|drive\.google\.com|onedrive\.live\.com|box\.com|s3\.amazonaws\.com)"
// Modify the regex above to include or exclude specific cloud services relevant to your environment
| summarize PostCount = count() by 
    DeviceName, 
    InitiatingProcessFileName, 
    InitiatingProcessCommandLine, 
    RemoteUrl
| where PostCount > 50  // Adjust based on typical usage in your organization
| order by PostCount desc
```

4. **Archive Collected Data**

This query detects the creation of archive files by unusual processes, which may signal data being prepared for exfiltration.

```kql
// Detect creation of archive files by unusual processes
DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName endswith '.zip' or FileName endswith '.rar' or FileName endswith '.7z' or FileName endswith '.tar.gz'
// Add or remove file extensions above to match archive formats used in your environment
| where InitiatingProcessFileName !in~ ('explorer.exe', 'winrar.exe', '7z.exe', 'tar.exe')  // Exclude known archiving tools; add any others used legitimately
| project Timestamp, 
    DeviceName, 
    InitiatingProcessFileName, 
    InitiatingProcessCommandLine, 
    FolderPath, 
    FileName
| order by Timestamp desc
```

5. **Obfuscated Files or Information**

This query searches for the use of encryption tools or commands, potentially indicating data encryption before exfiltration.

```kql
// Detect usage of encryption tools and commands
DeviceProcessEvents
| where ProcessCommandLine has_any ("gpg", "openssl", "certutil", "encrypt", "gpg.exe", "openssl.exe", "certutil.exe")
// Modify the list above to include or exclude encryption tools and keywords relevant to your environment
| project Timestamp, 
    DeviceName, 
    FileName, 
    ProcessCommandLine, 
    InitiatingProcessFileName, 
    InitiatingProcessCommandLine
| order by Timestamp desc

```
