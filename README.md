# Incident Response Report — Simulated Phishing-to-Malware Attack

**Analyst:** Deep Vyas
**Environment:** SOC-Lab-Win11 (isolated VirtualBox VM)
**Date of Investigation:** August 19, 2026
**Classification:** Lab Simulation — Controlled Test Environment

---

## 1. Incident Summary

A simulated phishing attack was investigated on host `SOC-Lab-Win11`. The scenario modeled a user opening a malicious email attachment, which was detected and quarantined by Windows Defender. Post-execution analysis of endpoint telemetry (Sysmon) revealed a process chain consistent with real-world post-compromise behavior: a suspicious child process spawn, an outbound network connection attempt from a scripting interpreter, and the creation of a scheduled task for persistence. All activity was correlated using Splunk, ingesting Windows Defender, Sysmon, and Windows Security event logs from the affected host.

## 2. Timeline of Events

| Time (8/19/2026) | Event | Source | Detail |
|---|---|---|---|
| (prior) | Malicious attachment delivered and detected | Windows Defender (Event 1116/1117) | EICAR test file identified as `Virus:DOS/EICAR_Test_File`, quarantined |
| 4:09:25 PM | Suspicious child process spawned | Sysmon EventCode=1 | `powershell.exe` → `notepad.exe` |
| 4:10:28 PM | Outbound connection attempt | Sysmon EventCode=3 | `powershell.exe` → microsoft.com:443 (simulated C2 callback) |
| 4:11:39 PM | Persistence mechanism created | Sysmon EventCode=1 | `powershell.exe` → `schtasks.exe /create /tn "UpdateCheck" /tr "notepad.exe" /sc onlogon /rl highest` |
| 4:12:01 PM | Persistence verified by attacker | Sysmon EventCode=1 | `powershell.exe` → `schtasks.exe /query /tn "UpdateCheck"` |

All timestamps captured directly from Splunk search results during investigation (`index=main` on host `SOC-Lab-Win11`).

## 3. Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| File (simulated malware) | `eicar_test2.txt` — detected as `Virus:DOS/EICAR_Test_File` |
| Parent process | `powershell.exe` |
| Suspicious child processes | `notepad.exe`, `schtasks.exe` |
| Scheduled task name | `UpdateCheck` |
| Task trigger | `onlogon`, run level `highest` (elevated privileges) |
| Network destination | `microsoft.com:443` (benign test destination; in a real incident this field is the priority pivot point) |
| Host | `SOC-Lab-Win11` |

## 4. Root Cause / Initial Access Vector

Simulated phishing email with malicious attachment (represented by the EICAR standard test file). Real-world equivalent: a macro-enabled document or executable disguised as a legitimate attachment, delivered via email and executed by the end user.

## 5. Impact Assessment

- **Scope:** Contained to a single isolated lab VM; no lateral movement observed or possible in this environment
- **Data exposure:** None — no actual malicious payload executed, all actions were controlled simulations
- **Persistence:** A scheduled task was successfully created, demonstrating the attacker's ability to maintain access across reboots if left unremediated

## 6. Remediation Steps Taken

1. Malicious file quarantined by Windows Defender automatically
2. Scheduled task persistence mechanism identified via Sysmon telemetry
3. Recommended removal command (to be executed by responder):
   ```
   schtasks /delete /tn "UpdateCheck" /f
   ```

## 7. Recommendations

- Restrict PowerShell execution policy on endpoints where scripting is not a business requirement
- Alert on scheduled tasks created by non-administrative processes or outside change-management windows
- Alert on outbound network connections initiated directly by `powershell.exe` or other scripting interpreters
- Conduct phishing awareness training focused on attachment handling
- Consider Attack Surface Reduction (ASR) rules to block Office applications from spawning child processes such as PowerShell

## 8. Detection Rule Reference

This investigation builds on the brute-force detection lab (Project 1). A complementary detection rule for this scenario would monitor for:
```
index=main EventCode=1 ParentImage="*powershell*" (Image="*schtasks*" OR Image="*notepad*")
```
flagging PowerShell-spawned processes for review — the same investigative technique used above, converted into a proactive alert.

## 9. Screenshots

<img width="532" height="413" alt="Screenshot 2026-08-19 at 3 49 13 PM" src="https://github.com/user-attachments/assets/b38cafeb-e069-4762-bf17-d09626db91b7" />

<img width="552" height="409" alt="Screenshot 2026-08-19 at 3 54 56 PM" src="https://github.com/user-attachments/assets/cee95ee3-86d7-4885-9341-084b44836261" />

<img width="1790" height="1075" alt="Screenshot 2026-08-19 at 4 08 17 PM" src="https://github.com/user-attachments/assets/abedebb9-cce3-4fd5-b716-fe50daa18341" />

<img width="1786" height="894" alt="Screenshot 2026-08-19 at 4 17 24 PM" src="https://github.com/user-attachments/assets/33b9ad85-1628-440d-ae1e-8ae5e6f881f0" />

<img width="879" height="648" alt="Screenshot 2026-08-19 at 4 18 04 PM" src="https://github.com/user-attachments/assets/1477d596-1ab6-4737-bdb9-86411bdeae19" />

<img width="869" height="828" alt="Screenshot 2026-08-19 at 4 18 34 PM" src="https://github.com/user-attachments/assets/233ce699-0ef4-440c-9416-859321686141" />





