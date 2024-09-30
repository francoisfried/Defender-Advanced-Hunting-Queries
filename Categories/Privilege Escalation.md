# Privilege Escalation

## Notes:
- Each script includes a comment on which part should be customized, such as file hashes, IPs, or specific system directories, to suit your organization's environment.
- Ensure your query is designed to avoid false positives by fine-tuning based on local network behavior or naming conventions.

---

1. **Detect suspicious use of `whoami` command**
   ```kql
   // Optionally add other privilege-related commands to the search criteria
   DeviceProcessEvents
   | where ProcessCommandLine contains "whoami"
   | project DeviceName, ProcessCommandLine, Timestamp
   ```

2. **Detect new administrative account creation**
   ```kql
   // Adjust "Administrators" group if you have other privileged groups
   IdentityInfo
   | where IdentityType == "User" and AccountDomain == "Administrators"
   | project AccountName, Timestamp
   ```

3. **Unusual process started by `SYSTEM` user**
   ```kql
   // Add more specific filtering for processes you deem suspicious for SYSTEM account usage
   DeviceProcessEvents
   | where InitiatingProcessAccountName == "SYSTEM"
   | project DeviceName, ProcessCommandLine, Timestamp
   ```

4. **Detect abnormal group membership changes**
   ```kql
   // Change the "Administrators" group based on other groups being monitored in your organization
   IdentityInfo
   | where AccountDomain == "Administrators" and ActionType == "GroupAdded"
   | project AccountName, Timestamp
   ```

5. **Detect use of privileged service accounts**
   ```kql
   // Modify "svc" to match naming conventions for service accounts in your environment
   DeviceLogonEvents
   | where AccountName contains "svc" and LogonType == "Interactive"
   | project DeviceName, AccountName, Timestamp
   ```
