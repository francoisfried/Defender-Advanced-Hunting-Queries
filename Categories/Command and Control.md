# Command and Control (C2)

## Notes:
- Each script includes a comment on which part should be customized, such as file hashes, IPs, or specific system directories, to suit your organization's environment.
- Ensure your query is designed to avoid false positives by fine-tuning based on local network behavior or naming conventions.

---

1. **Detect unusual outbound traffic**
   ```kql
   // This query identifies outbound traffic to public IPs on non-standard ports (above 1024). 
   // Adjust RemotePort or RemoteIPType based on your organization's network behavior.
   DeviceNetworkEvents
   | where RemoteIPType == "Public" and RemotePort > 1024
   | summarize count() by RemoteIP
   | sort by count_ desc
   ```

2. **Identify devices communicating with suspicious IPs**
   ```kql
   // Edit the list of known malicious IPs to suit your environment
   DeviceNetworkEvents
   | where RemoteIP in ("known_bad_ip_1", "known_bad_ip_2")
   | project DeviceName, RemoteIP, RemotePort, Timestamp
   ```

3. **Unusual DNS requests**
   ```kql
   // Adjust RemotePort if looking at different DNS services; customize domain TLDs if necessary
   DeviceNetworkEvents
   | where RemotePort == 53 and not (RemoteIP contains ".com" or RemoteIP contains ".org")
   | project DeviceName, RemoteIP, Timestamp
   ```
