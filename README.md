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
