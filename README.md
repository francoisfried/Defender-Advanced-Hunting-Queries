# Microsoft Defender Advanced Hunting KQL Queries

## Overview

This repository contains KQL (Kusto Query Language) queries for **Microsoft Defender Advanced Hunting**, organized around the **MITRE ATT&CK** framework. Each query helps security teams detect, investigate, and respond to adversary behavior by focusing on specific techniques identified within the MITRE ATT&CK matrix.

The **MITRE ATT&CK** framework provides a comprehensive matrix of **tactics** and **techniques** used by adversaries in cyber attacks. Understanding these techniques can enhance an organization's ability to defend against sophisticated threats by identifying potential vulnerabilities and implementing effective defenses.

---

## Tactics and Techniques Overview

Below is a summary of the **MITRE ATT&CK tactics** and the number of techniques associated with each. These tactics represent stages in an adversary’s attack lifecycle, and the techniques describe specific methods adversaries use to achieve their objectives.

| **Tactic**               | **Number of Techniques** |
|--------------------------|--------------------------|
| **Reconnaissance**        | 10                       |
| **Resource Development**  | 8                        |
| **Initial Access**        | 10                       |
| **Execution**             | 14                       |
| **Persistence**           | 20                       |
| **Privilege Escalation**   | 14                       |
| **Defense Evasion**       | 43                       |
| **Credential Access**     | 17                       |
| **Discovery**             | 32                       |
| **Lateral Movement**      | 9                        |
| **Collection**            | 17                       |
| **Command and Control**   | 18                       |
| **Exfiltration**          | 9                        |
| **Impact**                | 14                       |

This structure is crucial for organizing defensive strategies and **threat detection** methodologies. By aligning detection and hunting queries with specific techniques, this repository helps security teams stay ahead of adversaries.

---

## Repository Structure

The queries in this repository are categorized by the MITRE ATT&CK tactics. Under each tactic, you’ll find KQL queries that help detect specific techniques employed by attackers. Below is a brief description of each tactic:

### 1. **Reconnaissance**
Techniques adversaries use to gather information before gaining access to your network. Detection here focuses on **pre-access activities** such as scanning or collecting information from publicly available sources.

### 2. **Resource Development**
Techniques adversaries use to establish, compromise, or build resources they need to conduct operations. Detection queries here identify **malicious infrastructure setup** or use of compromised credentials.

### 3. **Initial Access**
Techniques used by adversaries to gain entry into your network. These queries focus on detecting attacks like **phishing, exploiting public-facing applications**, and other methods of initial compromise.

### 4. **Execution**
These techniques involve the execution of malicious code or commands. Detection queries focus on **malicious queries, PowerShell commands**, or the misuse of legitimate tools.

### 5. **Persistence**
Techniques adversaries use to maintain their access to systems across reboots, changed credentials, or other interruptions. **Registry modifications, scheduled tasks**, and other persistence techniques are covered here.

### 6. **Privilege Escalation**
Techniques used to gain higher-level permissions or privileges on the system. These include **exploiting vulnerabilities**, abusing trusted system functions, or using stolen credentials to elevate privileges.

### 7. **Defense Evasion**
Techniques used to avoid detection or bypass security controls. This is the largest tactic category with **43 techniques**, covering methods like **obfuscation, disabling security tools**, and manipulating logs.

### 8. **Credential Access**
Techniques for stealing credentials like **passwords, tokens**, or other authentication information. This category includes queries that detect tools or actions aimed at harvesting credentials.

### 9. **Discovery**
Techniques used to gain knowledge about the target environment, such as discovering **network topology, user accounts, and system services**. Detection queries in this category help spot abnormal **scanning or enumeration** activities.

### 10. **Lateral Movement**
Techniques used to move through a network from one system to another. Detection of **RDP, SMB abuse**, or the use of legitimate admin tools for lateral movement is covered here.

### 11. **Collection**
Techniques for gathering data of interest from a compromised environment. queries in this category identify activities like **data staging, screen capturing**, and the collection of sensitive files.

### 12. **Command and Control (C2)**
Techniques adversaries use to communicate with and control compromised systems. Detection of **malicious network traffic, web shells**, or suspicious **communication protocols** is key here.

### 13. **Exfiltration**
Techniques used to steal data from your environment. Detection of **data being exfiltrated over different channels** or through C2 communication is critical in this category.

### 14. **Impact**
Techniques aimed at **disrupting or destroying systems and data**, such as ransomware deployment, system wiping, or encryption for impact. Detection here focuses on **data destruction, service manipulation**, and other destructive actions.

---

## How to Use

Each KQL query is aligned with a specific **MITRE ATT&CK technique** and can be run directly within **Microsoft Defender Advanced Hunting**. Follow these steps to use the queries:

1. **Navigate to the relevant tactic**: Choose the folder that aligns with the MITRE ATT&CK tactic you are investigating or defending against.
2. **Select the appropriate query**: Select the KQL query associated with the technique you want to detect.
3. **Customize the query**: Modify the query for your environment, such as IP ranges, file paths, or specific threats you're targeting. Refer to the comment lines for guidance on which portions to edit.
4. **Run the query**: Paste the KQL query into the Microsoft Defender Advanced Hunting interface and run the query to gather relevant data.

---

## Citations

This repository utilizes both the **Microsoft Defender Advanced Hunting** feature and the **MITRE ATT&CK®** framework to structure and enhance detection of adversarial tactics, techniques, and procedures (TTPs). Below are the citations and brief descriptions of both resources:

- **Microsoft Defender for Endpoint - Advanced Hunting**  
  Microsoft Defender Advanced Hunting is a query-based threat-hunting tool available within Microsoft Defender for Endpoint. It allows security teams to proactively investigate and detect threats across endpoints using Kusto Query Language (KQL). Advanced Hunting provides visibility into endpoint data and network events, enabling rapid detection and response.  
  Available: [Microsoft Defender Advanced Hunting](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/advanced-hunting-overview)

- **MITRE ATT&CK®**  
  MITRE ATT&CK is a globally-accessible knowledge base of adversarial tactics, techniques, and procedures based on real-world observations. It is widely used by cybersecurity professionals to model threats, assess security postures, and develop detection strategies. The ATT&CK framework helps organizations understand and respond to the full spectrum of cyberattacks.  
  Available: [MITRE ATT&CK](https://attack.mitre.org)

---

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.
