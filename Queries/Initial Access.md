# Initial Access

## Notes:
- Each script includes a comment on which part should be customized, such as file hashes, IPs, or specific system directories, to suit your organization's environment.
- Ensure your query is designed to avoid false positives by fine-tuning based on local network behavior or naming conventions.

---

1. **Spearphishing Attachment**

This query detects the execution of malicious attachments delivered via email, focusing on suspicious processes spawned by email clients or opening of files with common phishing extensions.

```kql
// Detect execution of suspicious attachments from email clients
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("outlook.exe", "thunderbird.exe", "winmail.exe")
    // Add other email client executables relevant to your environment
| where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".scr" or FileName endswith ".hta"
    // Modify the list of extensions based on common malicious attachment types
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

2. **Drive-by Compromise**

This query detects the execution of scripts or downloads initiated by web browsers, which may indicate a drive-by compromise.

```kql
// Detect execution of scripts or downloads initiated by web browsers
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("chrome.exe", "firefox.exe", "iexplore.exe", "edge.exe", "safari.exe")
    // Add or remove browsers as necessary
| where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".js" or FileName endswith ".vbs"
    // Include file types that could be maliciously downloaded
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, 
InitiatingProcessParentFileName
| order by Timestamp desc
```

---

3. **Exploit Public-Facing Application**

This query detects suspicious processes or commands executed by public-facing applications, which may indicate exploitation attempts.

```kql
// Detect suspicious commands executed by public-facing applications
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("w3wp.exe", "httpd.exe", "nginx.exe", "tomcat.exe")
    // Add other public-facing application processes as needed
| where ProcessCommandLine has_any ("cmd.exe", "powershell.exe", "whoami", "net user", "nslookup")
    // Include commands that are uncommon for these applications to execute
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

4. **External Remote Services**

This query identifies successful remote desktop or SSH connections from external IP addresses, which may indicate unauthorized access.

```kql
// Detect successful remote connections from external IPs
DeviceLogonEvents
| where LogonType == "RemoteInteractive"
| where RemoteIP != "127.0.0.1" and RemoteIP != "::1"  // Exclude localhost
| where isnotempty(RemoteIP)
| extend RemoteIPType = iff(ipv4_is_private(RemoteIP), "Private", "Public")
| where RemoteIPType == "Public"
| summarize LogonCount = count() by AccountName, RemoteIP, DeviceName
| order by LogonCount desc
```

---

5. **Valid Accounts**

This query detects the creation of new user accounts or addition of users to privileged groups, which may indicate the use of valid accounts for initial access.

```kql
// Detect creation of new user accounts or privilege escalation
DeviceEvents
| where ActionType in ("UserAccountCreated", "UserAddedToGroup")
| extend ParsedFields = parse_json(AdditionalFields)
| extend GroupName = tostring(ParsedFields.TargetGroupName)
| where ActionType == "UserAddedToGroup" and GroupName in ("Admin", "Remote Desktop Users", "Domain Admins")
    // Adjust group names based on your environment
| project Timestamp, DeviceName, ActionType, AccountName, InitiatingProcessAccountName, GroupName
| order by Timestamp desc
```
