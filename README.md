**Threat Event (Stolen Credentials used for Lateral Movement and Data Exfiltration via Legitimate Cloud Service)**

**Scenario Title:**  Detecting Credential Theft and Exfiltration via OneDrive Misuse

**Reason for Hunt:**  Unusual System Behavior & Cybersecurity News

*   **Unusual System Behavior:**  The Security Operations Center (SOC) received an alert from the SIEM regarding an unusual spike in failed login attempts for a single user account, "jsmith," followed by a successful login from an unusual geographic location (outside the company's normal operating areas). This alone might be a false positive (e.g., user on vacation), but it warrants further investigation.
* **Cybersecurity News:** A recent report detailed a new phishing campaign targeting employees with fake "HR Policy Updates," that use highly obfuscated PowerShell scripts. The security team needs to evaluate.

**Hypothesis:**  An attacker successfully phished "jsmith," stole their credentials, used them to log in, deployed a script to extract sensitive data, and then exfiltrated that data via a legitimate cloud service (OneDrive) to blend in with normal traffic.

**Steps the "Bad Actor" Took (Create Logs and IoCs):**

1. Sent a phishing email to "jsmith" containing a malicious link or attachment.
2. Upon interaction with the phishing email, the user's credentials (username and password) were captured.
3. The attacker used "jsmith's" credentials to successfully log in to the corporate network from a remote location (different IP address than usual).
4. The attacker executed a PowerShell script, possibly hidden within a downloaded document or launched directly via a command-line interface.  The script's purpose is to:
    *   Search for files matching specific keywords (e.g., "confidential," "financial," "customer data").
    *   Compress these files into a single archive (e.g., `sensitive_data.zip`).
    *   Use the OneDrive command-line tool (which is legitimately installed on most corporate machines) to upload the archive to the attacker's personal OneDrive account.
5. The compressed archive (`sensitive_data.zip`) is uploaded to the attacker's OneDrive account.
6. The attacker deleted the `sensitive_data.zip` to avoid any immediate detection, as well as deleted the powershell script file they used.

**Tables Used to Detect IoCs:**

| Parameter            | Description                                                                                                                   |
| :------------------- | :---------------------------------------------------------------------------------------------------------------------------- |
| **Name**             | `IdentityLogonEvents`                                                                                                        |
| **Info**             | (Assumes integration with Identity Provider logs - e.g., Azure AD)  This table isn't a standard Defender table, but represents the type of data you'd need. |
| **Purpose**          | Detecting successful and failed logins, including location and IP address information.                                        |
| **Name**             | `DeviceProcessEvents`                                                                                                      |
| **Info**             | [https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)                                   |
| **Purpose**          | Detecting PowerShell execution, especially with suspicious command-line arguments, and the creation of the archive file.   |
| **Name**             | `DeviceFileEvents`                                                                                                         |
| **Info**             | [https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table)                                     |
| **Purpose**          | Detecting the creation and deletion of the `sensitive_data.zip` file, and identifying any files accessed by the PowerShell script. |
| **Name**             | `DeviceNetworkEvents`                                                                                                    |
| **Info**             | [https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table)                                  |
| **Purpose**          | Detecting network connections to OneDrive, specifically initiated by the `onedrive.exe` process, and identifying the amount of data transferred. |

**Related Queries (KQL - Microsoft Defender for Endpoint/XDR):**

```kql
// 1. Investigate the suspicious login activity for user "jsmith"
//This needs to be translated to the correct log, but for the example, we will use a general statement
// IdentityLogonEvents
// | where AccountName == "jsmith"
// | where LogonType == "Interactive" // Or the appropriate logon type
// | where Timestamp > ago(24h) // Look at the last 24 hours, adjust as needed
// | summarize LoginCount = count(), FailedCount = countif(Result == "Failed"), Locations = dcount(IPAddress) by Timestamp
// //This would need to be further modified to check if the Locations is outside the pre-defined list

// 2. Find PowerShell execution with potential obfuscation or unusual parameters
DeviceProcessEvents
| where InitiatingProcessFileName =~ "powershell.exe"
| where Timestamp > ago(24h) // Correlate with the login timeframe
| where ProcessCommandLine contains "-enc" or ProcessCommandLine contains "-nop" or ProcessCommandLine contains "-w hidden" // Basic obfuscation indicators
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, FileName

// 3. Look for file compression activity (creation of .zip files)
DeviceFileEvents
| where FileName endswith ".zip"
| where ActionType == "FileCreated"
| where Timestamp > ago(24h)
| project Timestamp, DeviceName, AccountName, FileName, FolderPath

// 4. Check for OneDrive usage, particularly large uploads
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "onedrive.exe"
| where Timestamp > ago(24h)
| where RemoteUrl contains "onedrive.live.com" // Or the relevant OneDrive URL
//The below line would only apply to a specific MDE version.
// | where ReceivedBytes > 10000000 // Threshold for large uploads (adjust as needed - 10MB)
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteUrl, RemoteIP, ReceivedBytes, SentBytes

//5. Check if the powershell script file has been deleted.  We'll look for "exfil.ps1"
DeviceFileEvents
| where FileName == "exfil.ps1"
| where ActionType == "FileDeleted"
| project Timestamp, DeviceName, FileName, FolderPath

// 6. Correlate findings:  This is the "impressive" part
//    We'll use a simplified join, but in a real hunt, you'd refine this.
let SuspiciousLogins = 
    IdentityLogonEvents
	//This needs to be translated to the correct log, but for the example, we will use a general statement
    // | where AccountName == "jsmith"
     //| where LogonType == "Interactive"
    // | where Timestamp > ago(24h)
     //And is not in a allow-list of IPs;
let SuspiciousPowerShell =
    DeviceProcessEvents
    | where InitiatingProcessFileName =~ "powershell.exe"
    | where Timestamp > ago(24h)
    | where ProcessCommandLine contains "-enc" or ProcessCommandLine contains "-nop" or ProcessCommandLine contains "-w hidden";
let SuspiciousFiles =
    DeviceFileEvents
    | where FileName endswith ".zip"
    | where ActionType == "FileCreated"
    | where Timestamp > ago(24h);
let SuspiciousOneDrive =
    DeviceNetworkEvents
    | where InitiatingProcessFileName =~ "onedrive.exe"
    | where Timestamp > ago(24h)
    | where RemoteUrl contains "onedrive.live.com";
SuspiciousPowerShell
| join kind=inner (SuspiciousFiles) on DeviceName, $left.Timestamp between ($right.Timestamp-1h .. $right.Timestamp+1h)
| join kind=inner (SuspiciousOneDrive) on DeviceName, $left.Timestamp between ($right.Timestamp-1h .. $right.Timestamp+1h)
//Add the Login events if you have them
//| join kind=inner (SuspiciousLogins) on AccountName, $left.Timestamp between ($right.Timestamp-24h .. $right.Timestamp)
| project Timestamp, DeviceName, AccountName, SuspiciousPowerShell.ProcessCommandLine, SuspiciousFiles.FileName, SuspiciousOneDrive.RemoteUrl, SuspiciousOneDrive.SentBytes
```

