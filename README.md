# Windows Threat Hunting Lab

## Overview

This project documents a hands-on Windows threat hunting investigation using Sysmon and Windows Event Viewer. The goal was to generate endpoint activity, analyze the resulting telemetry, and determine whether the observed behavior was benign, suspicious, or malicious.

During the investigation, I analyzed PowerShell process execution, system and account discovery, authentication activity, service installations, and scheduled tasks. Rather than relying on individual events alone, I correlated multiple Windows and Sysmon events to understand the context surrounding the activity and make a final analyst assessment.

## Lab Environment

- Windows 11 Virtual Machine
- Sysmon
- Sysmon Modular Configuration
- Windows Event Viewer
- PowerShell
- Windows Security Event Logs

## Investigation Objectives

The investigation focused on answering the following questions:

- What processes and PowerShell commands were executed?
- Which user account initiated the activity?
- What discovery actions were performed?
- Was there evidence of suspicious authentication activity?
- Were new services or scheduled tasks created?
- Did the collected evidence indicate benign, suspicious, or malicious behavior?

## Telemetry Setup

To collect detailed endpoint telemetry, I installed Sysmon on the Windows 11 virtual machine using the Sysmon Modular configuration. The configuration was validated successfully, and the Sysmon driver and service were started.

This provided additional visibility into system activity such as process creation, network connections, and file creation events that could be investigated through Windows Event Viewer.

### Sysmon Installation

The screenshot below shows the successful validation of the Sysmon configuration and the Sysmon service starting on the endpoint.

<img width="2940" height="1912" alt="image" src="https://github.com/user-attachments/assets/9db13362-6b9b-473c-843f-0a5f6e075e5e" />
## Investigation Activity

After confirming that Sysmon was collecting telemetry, I generated activity on the endpoint using PowerShell and investigated the resulting events in Sysmon and Windows Security logs.

I began by examining Sysmon Event ID 1 (Process Creation) to identify executed processes, command-line arguments, the user responsible for execution, and related process information.

### PowerShell Account Discovery

Analysis of Sysmon Event ID 1 identified PowerShell being used to enumerate local user accounts on the endpoint. The command collected each account's name, enabled status, and last logon information and wrote the results to a text file for review.

The event also identified `Vul-Lab-VM\azureuser` as the user associated with the process execution.

**Observed command:**

`Get-LocalUser | Select-Object Name,Enabled,LastLogon | Out-File C:\ThreatHuntLab\Investigation\local-users.txt`
<img width="2940" height="1912" alt="image" src="https://github.com/user-attachments/assets/d392403a-dbea-4672-baba-6d2c509d4598" />
### Analyst Interpretation

Local account discovery can be performed for legitimate administrative purposes, but it can also be used during reconnaissance to understand available accounts on a compromised system.

Because the command itself does not establish malicious intent, I treated the activity as suspicious enough to investigate further rather than immediately classifying it as malicious.

To determine whether the discovery activity was part of a larger attack, I expanded the investigation into authentication activity, additional PowerShell execution, services, and scheduled tasks.

## Authentication Analysis

To determine whether the PowerShell and account discovery activity was associated with unauthorized access, I reviewed Windows Security authentication events, focusing on Event IDs 4624 (successful logon) and 4625 (failed logon).

One reviewed Event ID 4624 showed a successful logon involving the **SYSTEM** account under **NT AUTHORITY**. The event recorded **Logon Type 5**, which represents a service logon rather than an interactive user logon.

**Key Event Details:**
- Event ID: 4624
- Target User: SYSTEM
- Target Domain: NT AUTHORITY
- Logon Type: 5
- Authentication Package: Negotiate
  <img width="2940" height="1912" alt="image" src="https://github.com/user-attachments/assets/63a0f73f-f61b-4c41-b4a8-a0366a9ec8dc" />
### Analyst Interpretation

The reviewed authentication activity was consistent with normal Windows service behavior. The Logon Type 5 event represented a service logging on under the SYSTEM account and did not, by itself, indicate unauthorized interactive access.

This reduced the likelihood that the previously observed account discovery activity was associated with credential-based intrusion. I continued the investigation by reviewing additional endpoint activity, including file creation, service installation, and scheduled task events.

## File Creation Analysis

I next reviewed Sysmon Event ID 11 (File Create) events to identify files created during the PowerShell activity.

One Event ID 11 showed `powershell.exe` creating a PowerShell script file within the user's temporary directory.

**Key Event Details:**
- Event ID: 11
- Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- Target Filename: `C:\Users\azureuser\AppData\Local\Temp\2_PSScriptPolicyTest_...ps1`
- User: `Vul-Lab-VM\azureuser`
  <img width="2940" height="1912" alt="image" src="https://github.com/user-attachments/assets/bc17398d-9a6a-455b-ae09-ac3b6b77b6e2" />
### Analyst Interpretation

The event confirmed that PowerShell generated a temporary `.ps1` file on the endpoint. Temporary PowerShell script creation can warrant investigation because PowerShell is frequently used for both legitimate administration and malicious execution.

However, the filename and location alone were not sufficient to classify the activity as malicious. I therefore correlated this event with the surrounding process, authentication, service, and scheduled task activity before making a final determination.

## Service Installation Analysis

I reviewed Windows System events for Event ID 7045 (A service was installed in the system) to determine whether the observed activity established persistence through the creation of a new Windows service.

The review identified several service installation events. One Event ID 7045 recorded the installation of the Sysmon64 service.

### Key Event Details

- Event ID: 7045
- Service Name: Sysmon64
- Service File Name: C:\Windows\Sysmon64.exe
- Service Type: User mode service
- Start Type: Auto start
- Service Account: LocalSystem
  <img width="2940" height="1912" alt="image" src="https://github.com/user-attachments/assets/83b37df0-2b51-4a49-9fa5-2b1983734eb2" />
### Analyst Interpretation

Event ID 7045 confirmed that a new Windows service was installed on the endpoint. Because service creation can be used as a persistence mechanism, I reviewed the service name, executable path, startup configuration, and service account before determining whether the activity was suspicious.

The service identified in this event was Sysmon64, running from `C:\Windows\Sysmon64.exe` with an automatic start configuration under the LocalSystem account. I correlated this event with the earlier installation of Sysmon performed during the telemetry setup phase of the investigation.

Although an automatically starting service running as LocalSystem could warrant further investigation in an unknown environment, the surrounding context explained this activity. The service installation was therefore assessed as expected administrative activity rather than evidence of malicious persistence.

## Scheduled Task Analysis

I reviewed Windows Task Scheduler events to determine whether scheduled tasks were being used as a persistence mechanism on the endpoint.

Task Scheduler Event ID 106 identified the registration of a new scheduled task.

### Key Event Details

- Event ID: 106
- Task Name: `\ThreatHuntLab-TestTask`
- User: `Vul-Lab-VM\azureuser`
- Event: Task registered

<img width="2940" height="1912" alt="image" src="https://github.com/user-attachments/assets/40f6d1cd-fc05-4b46-bd8d-e4cb1fc55e50" />


To determine the purpose of the task, I reviewed its configuration in Windows Task Scheduler. The configured action executed:

`cmd.exe /c echo ThreatHuntLab > C:\ThreatHuntLab\task-test.txt`

<img width="2940" height="1912" alt="image" src="https://github.com/user-attachments/assets/1efc8c5d-5269-4938-a149-ba255c9b9c43" />


### Analyst Interpretation

Scheduled tasks can be used legitimately for system administration, but they can also provide persistence by executing commands or programs automatically.

Because the task launched `cmd.exe`, I investigated the configured command rather than classifying the task based solely on the executable. The command only wrote the text `ThreatHuntLab` to a local test file and was consistent with the controlled activity generated during the investigation.

Based on the available evidence, the task was assessed as benign lab activity. However, the investigation demonstrated how Task Scheduler telemetry can be used to identify task creation and determine whether a scheduled action warrants further investigation.

## Failed Authentication Analysis

I reviewed Windows Security events for Event ID 4625 to identify failed authentication attempts and determine whether the activity warranted further investigation.

One Event ID 4625 recorded a failed logon attempt involving the account `NOUSER`.

### Key Event Details

- Event ID: 4625
- Account Name: NOUSER
- Account Domain: Vul-Lab-VM
- Logon Type: 8
- Failure Reason: Unknown user name or bad password
- Status: 0xC000006D
- Sub Status: 0xC0000064
- Caller Process: C:\Windows\System32\OpenSSH\sshd.exe
- Workstation Name: Vul-Lab-VM
  <img width="2940" height="1912" alt="image" src="https://github.com/user-attachments/assets/ae76a6a6-e0b1-4164-9591-542cff4fa85e" />
  ### Investigation

The failure reason reported an unknown username or bad password. The substatus code `0xC0000064` further indicated that the specified account did not exist.

I then reviewed the process associated with the authentication attempt. The caller process was:

C:\Windows\System32\OpenSSH\sshd.exe

This indicated that the failed authentication was associated with the Windows OpenSSH service. I also reviewed the network information recorded with the event. The event did not provide a source network address or source port, limiting attribution of the attempt to a specific remote system.
<img width="2940" height="1912" alt="image" src="https://github.com/user-attachments/assets/5cd5fe56-456f-4823-af92-59a07411fca2" />
<img width="2940" height="1912" alt="image" src="https://github.com/user-attachments/assets/810730ab-beee-492c-95e4-79f6e10a2ad4" />

### Analyst Interpretation

Failed authentication events can result from user error or legitimate system activity, but repeated failures, nonexistent usernames, or unusual source systems can also indicate password guessing or account enumeration.

In this event, the attempted account `NOUSER` did not exist and the authentication attempt was associated with `sshd.exe`. Because the event did not contain a source network address or port, I could not attribute the attempt to a specific remote host from this event alone.

I would correlate additional Event ID 4625 events, OpenSSH logs, source IP information, and successful logons occurring near the same time before determining whether the activity represented malicious authentication attempts.

## Skills Demonstrated

- Windows Event Log analysis using Event Viewer
- Investigation of failed authentication attempts (Event ID 4625)
- Analysis of Windows service installation activity (Event ID 7045)
- Identification of scheduled task creation (Event ID 106)
- Investigation of persistence-related activity
- Analysis of authentication failure codes and associated processes
- Distinguishing expected system activity from potentially suspicious behavior
- Evidence-based investigation and documentation

## Conclusion

This lab demonstrated a practical Windows threat-hunting workflow using native Windows telemetry. I investigated service installations, scheduled task creation, and failed authentication activity, then analyzed the surrounding context to determine whether each event represented expected or potentially suspicious behavior.

Rather than treating individual event IDs as inherently malicious, I used event details such as service paths, task actions, account information, failure codes, and associated processes to determine what occurred and what additional evidence would be required for escalation.
