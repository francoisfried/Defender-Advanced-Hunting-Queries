# Microsoft Defender Advanced Hunting KQL Scripts for Incident Response and Threat Hunting

## Overview

This repository contains a collection of KQL (Kusto Query Language) scripts for **Microsoft Defender Advanced Hunting**. These scripts are designed to help security teams with **incident response** and **threat hunting**. Each script falls under one of several categories, based on common attack vectors or malicious activities, and can be customized to suit specific environments.

The goal is to provide actionable, easily modifiable scripts that enhance detection of threats, suspicious activities, and potential compromises.

---

## Categories

The repository is organized into the following categories to help streamline the process of incident response and threat hunting in Microsoft Defender Advanced Hunting. Each category contains KQL scripts targeting specific activities or attack vectors.

### 1. **Malware Detection**
Queries to help identify the presence of malware, suspicious file executions, and other indicators of malicious software across endpoints.

### 2. **Suspicious Network Activity**
These scripts are designed to monitor and detect unusual or malicious network traffic, including scans, exfiltration, or command-and-control activity.

### 3. **Privilege Escalation**
Queries focused on detecting attempts by attackers to escalate their privileges within the environment, whether through new account creation, misuse of administrative privileges, or other techniques.

### 4. **Lateral Movement**
Scripts to detect adversaries moving across the network, typically using protocols like RDP, SMB, or PsExec, and techniques like WMI or remote service creation.

### 5. **Persistence Mechanisms**
Queries targeting persistence techniques attackers might use to maintain their foothold in compromised systems, such as scheduled tasks, registry modifications, or service creation.

---

## How to Use

Each script comes with comments indicating which part of the query can be customized to fit your specific environment or investigation needs. **To use these queries**:

1. Go to Microsoft Defender's Advanced Hunting interface.
2. Copy and paste the desired KQL script into the query editor.
3. Modify the customizable parts (such as file hashes, IP addresses, or directory paths) based on the investigation or your organizational setup.
4. Run the query and analyze the results.

For each category, you'll find different scripts tailored for different hunting or response scenarios. Modify the queries as necessary to align them with your specific network, systems, or threat profiles.

---

## Customization Notes

Throughout the scripts, you'll find **comment lines** explaining what to customize. These usually relate to:
- **File hashes**: Replace with known malicious hashes you're investigating.
- **IP addresses**: Replace with suspicious or malicious IPs relevant to your environment.
- **Directory paths**: Customize based on folder structures commonly used in your organization.
- **Process names/commands**: Modify to match the specific behavior you're targeting (e.g., PowerShell commands or PsExec usage).

---

## Contributing

We welcome contributions! If you have additional KQL scripts or enhancements to the existing ones, feel free to submit a pull request.

- **Fork** the repository
- **Create** a new branch for your changes
- **Submit** a pull request with a clear description of what you are adding or modifying

---

## License

This repository is licensed under the MIT License. Feel free to use, modify, and share as needed, but please give credit to this repository where applicable.

---

## Acknowledgements

Thanks to the broader security community and open-source contributors who continue to improve and share methods for defending against threats.
