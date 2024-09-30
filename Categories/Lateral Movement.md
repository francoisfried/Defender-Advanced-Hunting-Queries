# Lateral Movement

## Notes:
- Each script includes a comment on which part should be customized, such as file hashes, IPs, or specific system directories, to suit your organization's environment.
- Ensure your query is designed to avoid false positives by fine-tuning based on local network behavior or naming conventions.

---

1. **Detect RDP connections**
   ```kql
   // Adjust the port (3389) if your environment uses a non-standard port for RDP
   DeviceNetworkEvents
   | where RemotePort == 3389
   | project DeviceName, RemoteIP, Timestamp
   ```

2. **Detect abnormal SMB connections**
   ```kql
   // Customize RemotePort (445) if you use other SMB variants
   DeviceNetworkEvents
   | where RemotePort == 445
   | summarize count() by DeviceName, RemoteIP
   ```

3. **Detect use of `PsExec` tool**
   ```kql
   // Adjust based on known PsExec variants or command-line switches specific to your environment
   DeviceProcessEvents
   | where ProcessCommandLine contains "psexec"
   | project DeviceName, ProcessCommandLine, Timestamp
   ```

4. **Detect lateral movement via WMI**
   ```kql
   // Add other WMI commands of interest if your environment has variations
   DeviceProcessEvents
   | where ProcessCommandLine contains "wmic" and ProcessCommandLine contains "\\"
   | project DeviceName, ProcessCommandLine, Timestamp
   ```

5. **Detect remote service creation**
   ```kql
   // Modify "sc.exe create" if the attacker uses alternative service creation methods
   DeviceProcessEvents
   | where ProcessCommandLine contains "sc.exe" and ProcessCommandLine contains "create"
   | project DeviceName, ProcessCommandLine, Timestamp
   ```
