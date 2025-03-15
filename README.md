![image](https://github.com/user-attachments/assets/450a9ad8-f3b1-4eb7-99a2-6adf5c004cb5)

# Threat Hunt Report: System Compromise
- [Scenario Creation](https://github.com/AaronRMartinez/Threat-Hunting-Scenario-Compromise/blob/main/Threat-Hunting-Scenario-System-Compromise-Creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

##  Scenario

It is suspected that a machine within the enterprise was targeted by a brute-force attack. A high number of failed logon attempts was detected on the system, along with unusual activity in the event logs. The objective is to determine whether the attacker successfully gained access and whether any malicious actions were performed. If a compromise is confirmed, the incident response plan will be initiated.

### High-Level Malicious Activity IoC Discovery Plan

- **Check `DeviceLogonEvents`** for any failed or successful RDP logon attempts.
- **Check `DeviceProcessEvents`** for any signs of malicious activity.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections or file downloads.
- **Check `DeviceFileEvents`** for any signs of files being downloaded or created.
- **Check `DeviceRegistryEvents`** for any signs of registry modifications in the registry for persistence.


---

## Steps Taken

### 1. Searched the `DeviceLogonEvents` Table

Inspecting the `DeviceLogonEvents` table for relevant logs to the endpoint `arm-thcompromis`, several failed logon attemps to the user account `aaronmart` was observed. The failed logon attempts occurred in quick succession, indicating a brute force attack likely occurred. The brute force attack appeared to be successful because of successful login succeeding the failed attempts at `2025-03-15T15:02:10.5325975Z`.

**Query used to locate events:**

```kql
DeviceLogonEvents
| where DeviceName == "arm-thcompromis"
| project Timestamp, DeviceName, ActionType, LogonType, AccountName, FailureReason
```
![image](https://github.com/user-attachments/assets/01598b1a-c366-49f7-a5fd-eef612290d80)

---

### 2. Searched the `DeviceProcessEvents` Table

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

### 3. Searched the `DeviceNetworkEvents` Table for File Downloads

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2025-03-05T01:07:10.6041161Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "arm-threathunti"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/e899bf32-c262-4f24-bbe3-16bf40fe68fd)

---

### 4. Searched the `DeviceFileEvents` Table for File Creation Events

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-03-05T01:07:24.7605276Z`, an employee on the 'arm-threathunti' device successfully established a connection to the remote IP address `45.142.177.89` on port `443`. The connection was initiated by the process `tor.exe`, located in the folder `C:\users\aaronmart\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443` and '9001'.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "arm-threathunti"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("80", "443", "9001", "9030", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/4757d3cd-b515-4a23-8a78-2f2aec559de6)

---

### 4. Searched the `DeviceProcessEvents` Table for Executable Events

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-03-05T01:07:24.7605276Z`, an employee on the 'arm-threathunti' device successfully established a connection to the remote IP address `45.142.177.89` on port `443`. The connection was initiated by the process `tor.exe`, located in the folder `C:\users\aaronmart\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443` and '9001'.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "arm-threathunti"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("80", "443", "9001", "9030", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/4757d3cd-b515-4a23-8a78-2f2aec559de6)

---

### 4. Searched the `DeviceProcessEvents` Table for Malicious Script Activity

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-03-05T01:07:24.7605276Z`, an employee on the 'arm-threathunti' device successfully established a connection to the remote IP address `45.142.177.89` on port `443`. The connection was initiated by the process `tor.exe`, located in the folder `C:\users\aaronmart\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443` and '9001'.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "arm-threathunti"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("80", "443", "9001", "9030", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/4757d3cd-b515-4a23-8a78-2f2aec559de6)

---

### 4. Searched the `DeviceRegistryEvents` Table for Registry Modifications to Obtain Persistence 

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-03-05T01:07:24.7605276Z`, an employee on the 'arm-threathunti' device successfully established a connection to the remote IP address `45.142.177.89` on port `443`. The connection was initiated by the process `tor.exe`, located in the folder `C:\users\aaronmart\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443` and '9001'.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "arm-threathunti"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("80", "443", "9001", "9030", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/4757d3cd-b515-4a23-8a78-2f2aec559de6)

---

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

A RDP brute force attack targeted the user account "aaronmart" on the endpoint "arm-threatunti". The attacker successfully gained access to the machine and executed an "Invoke-WebRequest" command to download a malicious executable. The malicious executable was then executed, running several encoded PowerShell commands.  A compressed file was downloaded that contained several files intended for further exploitation. Subsequently, a scheduled task was created to establish persistence on the system. While network reconnaissance was also conducted by the malicious executable.

---

## Response Taken

A RDP Brute Force Attack was confirmed and verified to have been successful on the endpoint `arm-threathunti`, on the user account `aaronmart`. The device was isolated, and the security operations center was notified.

---
