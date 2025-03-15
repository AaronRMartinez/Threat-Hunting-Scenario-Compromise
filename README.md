# Threat Hunt Report: System Compromise
- [Scenario Creation](https://github.com/AaronRMartinez/Threat-Hunting-Scenario-Tor/blob/main/Threat-Hunting-Scenario-Tor-Event-Creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

##  Scenario

It is suspected that a machine within the enterprise was targeted by an RDP brute-force attack. A high volume of failed logon attempts was detected on the system, along with unusual activity in the event logs. The objective is to determine whether the attacker successfully gained access and whether any malicious actions were performed. If a compromise is confirmed, the incident response plan will be initiated.

### High-Level Malicious Activity IoC Discovery Plan

- **Check `DeviceLogonEvents`** for any failed or successful RDP logon attempts.
- **Check `DeviceProcessEvents`** for any signs of malicious activity.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections or file downloads.
- **Check `DeviceFileEvents`** for any signs of files being downloaded or created.
- **Check `DeviceRegistryEvents`** for any signs of registry modifications in the registry for persistence.


---

## Steps Taken

### 1. Searched the `DeviceLogonEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-03-05T01:24:05.3837414Z`. These events began at `2025-03-05T01:03:21.8806891Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "arm-threathunti"
| where InitiatingProcessAccountName == "aaronmart"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-03-05T01:03:21.8806891Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
![image](https://github.com/user-attachments/assets/5af94afe-e028-4e38-b435-fea10698cfbe)

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2025-03-05T01:05:56.8154496Z`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "arm-threathunti"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.7.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FolderPath, SHA256, ProcessCommandLine
```
![image](https://github.com/user-attachments/assets/f9d779ba-120b-47d1-897f-d81282452df1)

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

The user "aaronmart" on the "arm-threathunti" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `arm-threathunti` by the user `aaronmart`. The device was isolated, and the user's direct manager was notified.

---
