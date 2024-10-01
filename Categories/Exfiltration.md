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
