<h1>Incident Response: Brute Force Success - Azure Active Directory</h1>

- <b>This tutorial outlines the configuration of performing incident response for a successful brute force attempt on Azure Active Directory using Microsoft Sentinel and Log Analytics Workspace</b>

<h2>Environments and Technologies Used</h2>

- <b>Microsoft Azure</b> 
- <b>Microsoft Sentinel</b>
- <b>Log Analytics Workspace</b>

<h2>Operating Systems</h2>

- <b>Windows 10</b>

<h2>Configuration Steps</h2>

![image](https://github.com/user-attachments/assets/bb4d1cf1-7415-492e-a976-ef9c9cf3f77e)
- <b>Navigate to Microsoft Sentinel and click a CUSTOM: BRUTE FORCE SUCCESS Azure Active Directory incident</b>
- <b>Set Owner: Ryan Justin De Jesus, Status: Active, Severity: High</b>
- <b>Click view full details</b>

![image](https://github.com/user-attachments/assets/bdab9b12-a622-4d46-a803-1b9e8ff34c43)
- <b>Click activity log and observe the activity log</b>

![image](https://github.com/user-attachments/assets/c44b27d4-8239-4f74-a7c4-0addc001604e)
- <b>Investigate and determine the scope</b>
- <b>Click the IP Address and observe the related event</b>
- <b>This specific incident is related to 11+ events</b>

![image](https://github.com/user-attachments/assets/5d5120ac-978c-4f22-bfcd-fa4645433b23)
- <b>More Information is presented in the Log Analytics Workspace from this query:</b>

``` 
let GetIPRelatedAlerts = (v_IP_Address: string) {
    SecurityAlert
    | summarize arg_max(TimeGenerated, *) by SystemAlertId
    | extend entities = todynamic(Entities)
    | mv-expand entities
    | project-rename entity=entities
    | where entity['Type'] == 'ip' and entity['Address'] =~ v_IP_Address
    | project-away entity
};
GetIPRelatedAlerts(@'20.28.87.112')
```

```
SecurityEvent
| where EventID == 4625
| where IpAddress == '20.28.87.112'
```
 
![image](https://github.com/user-attachments/assets/3dbe1a9d-de07-44ee-b194-c952feb69564)
- <b>Determine the legitimacy of the incident (True Positive, False Positive,etc)</b>
- <b>Based on the results, I will conclude this as a False Positive - Inaccurate Data since this was from our host computer by the matching IP address. However, if this is a real incident, we have to investigate further and follow the playbook for successful brute force attempts on Azure Active Directory. If this is within the organization, I would call the user and confirm the details with them. If we determine that the user was doing normal duties as a pentester, and collaborated with their manager to conduct this. Then we can close it. False Positive - Inaccurate Data.

## Incident Management Playbook 
- <b>Incident Description</b>
    - This incident involves observation of potential brute force attempts against a Linux Syslog.

- <b>Initial Response Actions</b>
    - Verify the authenticity of the alert or report.
    - Immediately isolate the machine and change the password of the affected user
    - Identify the origin of the attacks and determine if they are attacking or involved with anything else
    - Determine how and when the attack occurred
        - Are the NSGs not being locked down? If so, check other NSGs
    - Assess the potential impact of the incident.
        - What type of account was it? Permissions?

## Containment and Recovery

![image](https://github.com/user-attachments/assets/86ee1b28-092f-4490-b5b1-c0bc58562da9)
- <b>Lock down the NSG assigned to that VM/Subnet, either entirely, or to allow only necessary traffic</b>

![image](https://github.com/user-attachments/assets/0f43e8a9-e329-405e-9467-d57dbbd165ab)
- <b>Reset the affected user’s password</b>
