# Collection

## Notes:
- Each script includes a comment on which part should be customized, such as file paths, file types, or specific processes, to suit your organization's environment.
- Ensure your query is designed to avoid false positives by fine-tuning based on local network behavior or naming conventions.

---

1. **Detect data staging in suspicious directories**
   ```kql
   // Edit the folder paths if attackers are known to use other directories in your environment
   DeviceFileEvents
   | where FolderPath contains "Temp" or FolderPath contains "Downloads" or FolderPath contains "AppData"
   | where FileName endswith ".zip" or FileName endswith ".rar" or FileName endswith ".7z"
   | project Timestamp, DeviceName, FolderPath, FileName, FileSize
   ```

2. **Detect large file transfers via SMB**
   ```kql
   // Adjust the file size threshold to fit your organization’s definition of "large files"
   DeviceNetworkEvents
   | where ActionType == "FileAccessed" and RemotePort == 445
   | where FileSize > 100000000  // Threshold set to 100 MB
   | project Timestamp, DeviceName, RemoteIP, FileName, FileSize
   ```

3. **Detect screen capture activity**
   ```kql
   // Customize process names if attackers are known to use other screenshot tools in your environment
   DeviceProcessEvents
   | where ProcessCommandLine contains "snippingtool.exe" or ProcessCommandLine contains "mspaint.exe" or ProcessCommandLine contains "screenshot"
   | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
   ```

4. **Detect sensitive file access**
   ```kql
   // Update the file types and folder paths based on the types of sensitive data in your organization
   DeviceFileEvents
   | where FileName endswith ".docx" or FileName endswith ".xlsx" or FileName endswith ".pdf"
   | where FolderPath contains "Documents" or FolderPath contains "Finance"
   | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName
   ```

5. **Detect clipboard access for potential data collection**
   ```kql
   // Edit the process names if attackers are known to use specific clipboard tools in your environment
   DeviceProcessEvents
   | where ProcessCommandLine contains "clip.exe" or ProcessCommandLine contains "powershell Get-Clipboard"
   | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
   ```
