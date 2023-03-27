![image](https://user-images.githubusercontent.com/115627299/216758052-65220c52-f1f4-43bd-895b-e6547298987e.png)
# check_wmi_os_security
**version: 0.84**

***:computer:  Script monitoring not only Windows security components by WMI. Tested on Windows Server 2019/2022 64-bit. Tested on Python version: 3.6.8.***

- Windows Firewall status monitoring
- Define your own WQL query and your own namespace. It is possible to monitor any WMI item there :) (Monitoring Windows Service, Windows Share, Windows Process, Disk partitions, etc.)
- Windows EventLog monitoring example ( small SIEM :smiley: ):
  - Monitoring user operations such as user creation, deletion, password change, locking, etc.
  - Monitoring dump memory (read RDP passwords cleartext/hash from memory)
  - Account login failed multiple times
  - Powershell security 'Set-ExecutionPolicy Bypass'
  - Windows Defender Antivirus (disable engine, found virus, etc.)
  - Symantec Antivirus (disable engine, found virus, etc.)
  - Scheduled task was created
  - etc.
- Windows Network monitoring
- Monitoring Windows Users (for example lockusers)
- Windows Uptime monitoring
- Windows Timezone monitoring
- Windows Domain/Workgroup monitoring
- Windows S/N monitoring, HW information (ideal for physical servers)
- OS information
etc.
<br>

&nbsp;
**Sample output**
![image](https://user-images.githubusercontent.com/115627299/217789039-5f3c1593-fe57-4011-a432-bf46a7ce56b1.png)


---
# How to configure the infrastructure for Windows monitoring using WMI. 'check_wmi_os_security' uses ['wmic_server'](https://github.com/cesbit/aiowmi/tree/main/contrib/wmic_server) for remote access to Windows WMI.
- [1. Creating a Group and an Account in Active Directory for Windows monitoring using WMI](#1-creating-a-group-and-an-account-in-active-directory-for-windows-monitoring-using-wmi)
- [2. Creating a GPO to distribute permissions](#2-creating-a-gpo-to-distribute-permissions-restricted-groups)
- [3. Firewall rules (allowing WMI from the monitoring engine server)](#3-firewall-rules-allowing-wmi-from-the-monitoring-engine-server)
   - [3.1 - Bulk using GPO](#31---bulk-using-gpo)
   - [3.2 - Manually (example for servers in the DMZ)](#32---manually-example-for-servers-in-the-dmz)
- [4. Setting WMI permissions on a Windows servers](#4-setting-wmi-permissions-on-a-windows-servers)
  - [4.1 - Batch script for bulk setup](#41-batch-script-for-bulk-setup)
  - [4.2 - Manual setting (example for servers in the DMZ)](#42---manual-setting-example-for-servers-in-the-dmz)
- [5. Installing wmic_server on Debian 11 (WMI monitoring from Linux server)](#5-installing-wmic_server-on-debian-11-wmi-monitoring-from-linux-server)
  - [5.1 - Functionality testing of wmic_server](#51---functionality-testing-of-wmic_server)
  - [5.2 - Configuring wmic_server to run as a service](#52---configuring-wmic_server-to-run-as-a-service)
- [6. Implementation of 'check_wmi_os_security'](#6-implementation-of-check_wmi_os_security)
- [7. GPO - Advanced audit configuration for a security log](#7-gpo---advanced-audit-configuration-for-a-security-log)
---


&nbsp;
# 1. Creating a group and an account in Active Directory for Windows monitoring using WMI
> Create a group and a user who will have permission to read WMI information from the servers in Microsoft domain.
- In the MMC console '**Active Directory Users and Computers**':
![image](https://user-images.githubusercontent.com/115627299/216756259-3e71d6b8-7f28-44f9-9f60-96d6299cbb79.png)
  - Create group (example '**WMI-monitoring-Group**'). The group is in AD for auditing access. Don't just use users put users in groups!  <br>
![image](https://user-images.githubusercontent.com/115627299/216756566-1f6f0093-c69c-4e2d-a480-4b9b1f1198f2.png)
  - Create user (example '**wmi-monitor**') <br>
![image](https://user-images.githubusercontent.com/115627299/216756556-368621e8-906c-4814-b662-3c00a215a746.png)
> Ideally set the password to 'Password never expires'<br>
![image](https://user-images.githubusercontent.com/115627299/216913772-0ea7258d-5633-4c47-b14d-ff3adacc5b5f.png)
- Add user '**wmi-monitor**' to group '**WMI-monitoring-Group**' <br>
![image](https://user-images.githubusercontent.com/115627299/216756369-6b7205a4-14be-4932-9b72-1476e63d3d2a.png)

<!-- 2. GPO FOR GROUP ----------------------------------------------------------------------------------------------------------------->

&nbsp;
# 2. Creating a GPO to distribute permissions (Restricted Groups)
- Create GPO for 'Restricted Groups'. Edit GPO and settings as shown in the picture.
  > Group Name: BUILTIN\Performance Monitor Users; BUILTIN\Event Log Readers; BUILTIN\Distributed COM Users
  ![image](https://user-images.githubusercontent.com/115627299/216756515-53dc59b7-c391-4b98-83a5-bdcbf72ae377.png)
  ![image](https://user-images.githubusercontent.com/115627299/216756623-e1243278-a8f6-406f-a8fc-ed19c7e0fae3.png)

> When implementing GPOs, you need to wait for replication between DCs and then apply to servers.
> For testing, it is possible to configure the GPO on the server side using: <br>

> Run Command Prompt 'cmd.exe' (Run as administrator)

```
gpupdate /force
```
![image](https://user-images.githubusercontent.com/115627299/216947867-f68f3de7-88a1-45de-a6cb-589afba2c404.png)


<!-- 3. FIREWALL ------------------------------------------------------------------------------------------------------------------------>

&nbsp;
# 3. Firewall rules (allowing WMI from the monitoring engine server)
>There are two options here ['3.1 - Bulk using GPO'](#31---bulk-using-gpo) or ['3.2 - Manually (example for servers in the DMZ)'](#32---manually-example-for-servers-in-the-dmz) click and click...(Manual setting is suitable for servers in DMZ).


&nbsp;
## 3.1 - Bulk using GPO
- Create GPO for FW rules. Add the following two rules. <br>
> IP address '172.16.60.210' to the IP from which you will run 'wmic_server'  ['5. Installing wmic_server on Debian 11 (WMI monitoring from Linux server)'](#5-installing-wmic_server-on-debian-11-wmi-monitoring-from-linux-server) <br>
> IP: 172.16.60.200 is the IP address of the server from which you will run the [script to add WMI permissions.](#4-setting-wmi-permissions-on-a-windows-servers).

&nbsp;
![image](https://user-images.githubusercontent.com/115627299/216959050-addb93da-6067-4460-ad5f-a1edb1f9e8b3.png)

> Only a sample of how to configure services.

&nbsp;
![image](https://user-images.githubusercontent.com/115627299/216944625-047efcd3-5820-4fd3-9575-03c0db477763.png)

> List of rules in the text.
```
00-WMI-Monitoring-DCOM  
This rule might contain some elements that cannot be interpreted by the current version of GPMC reporting module  
Enabled True 
Program %systemroot%\system32\svchost.exe 
Action Allow 
Security Require authentication 
Authorized computers  
Authorized users  
Protocol 6 
Local port 135 
Remote port Any 
ICMP settings Any 
Local scope Any 
Remote scope 172.16.60.210, 172.16.60.200 
Profile All 
Network interface type All 
Service RpcSs 
Allow edge traversal False 
Group  
 
00-WMI-Monitoring-WMI  
This rule might contain some elements that cannot be interpreted by the current version of GPMC reporting module  
Enabled True 
Program %systemroot%\system32\svchost.exe 
Action Allow 
Security Require authentication 
Authorized computers  
Authorized users  
Protocol 6 
Local port Any 
Remote port Any 
ICMP settings Any 
Local scope Any 
Remote scope 172.16.60.210, 172.16.60.200 
Profile All 
Network interface type All 
Service Winmgmt 
Allow edge traversal False 
Group 
```
> When implementing GPOs, you need to wait for replication between DCs and then apply to servers.
> For testing, it is possible to configure the GPO on the server side using: <br>
- Run Command Prompt 'cmd.exe' (Run as administrator)  <br>
![image](https://user-images.githubusercontent.com/115627299/216898352-0bee8d7b-f5c7-49c9-a0c4-10a40f1b2dbe.png)


```
gpupdate /force
```
![image](https://user-images.githubusercontent.com/115627299/216947867-f68f3de7-88a1-45de-a6cb-589afba2c404.png)


&nbsp;
## 3.2 - Manually (example for servers in the DMZ)
> I use manual settings for testing or servers in the DMZ
- Run Command Prompt 'cmd.exe' (Run as administrator)  <br>
![image](https://user-images.githubusercontent.com/115627299/216898352-0bee8d7b-f5c7-49c9-a0c4-10a40f1b2dbe.png)

- Adding two FW rules using CLI. Change the 'remoteip' IP address '172.16.60.210' to the IP from which you will run 'wmic_server' [( installation is in paragraph 5. )](#5-installing-wmic_server-on-debian-11-wmi-monitoring-from-linux-server).

> When adding FW rules manually, you also have to manually add WMi permissions [Manual WMI permissions](#42---manual-setting-example-for-servers-in-the-dmz). <br>
> The ['4.1 Batch Script for Bulk Setup'](#41-batch-script-for-bulk-setup) script will not work due to blocking personal FW. To use the script, it is necessary to add the remoteip IP from which we will run the script to the rules below. Here only remoteip is the IP of 'wmic_server'.
```
netsh advfirewall firewall add rule dir=in name="00-WMI-Monitoring-DCOM" program=%systemroot%\system32\svchost.exe service=rpcss action=allow protocol=TCP localport=135 remoteip=172.16.60.210
netsh advfirewall firewall add rule dir=in name ="00-WMI-Monitoring-WMI" program=%systemroot%\system32\svchost.exe service=winmgmt action = allow protocol=TCP localport=any remoteip=172.16.60.210
```
- Check in the GUI <br>
![image](https://user-images.githubusercontent.com/115627299/216902133-5622e7b3-2029-4bf5-90e7-5639eab9dce3.png)

&nbsp;
#### [ ONLY FOR DMZ SERVERS ] If you have a server in the DMZ, you need to set a fixed TCP port for WMI (Setting FW rule to Central FW). By default, WMI works on dynamic TCP ports after connection negotiation https://learn.microsoft.com/windows/win32/wmisdk/setting-up-a-fixed-port-for-wmi?redirectedfrom=MSDN

- Run Command Prompt 'cmd.exe' (Run as administrator) <br>
![image](https://user-images.githubusercontent.com/115627299/216898352-0bee8d7b-f5c7-49c9-a0c4-10a40f1b2dbe.png)

```
  #----------------------------------------------------------------------------
  #Fixed Port for WMI
  #----------------------------------------------------------------------------

  ##Enable. Nativne TCP port is TCP/24158
  winmgmt -standalonehost
  net stop winmgmt
  net stop "Windows Management Instrumentation"
  net start "Windows Management Instrumentation"
  net start winmgmt
  ```

- Add rule for personal Firewall.

```
netsh firewall add portopening protocol=TCP port=24158 name=00-WMI-Monitoring-WMI-WMIFixedPort mode=ENABLE scope=CUSTOM addresses=172.16.60.210
```


<!-- 4. WMI PERMISSIONS  ----------------------------------------------------------------------------------------------------------------->

&nbsp;
# 4. Setting WMI permissions on a Windows servers
> There are two options here ['4.1 Batch script for bulk setup'](#41-batch-script-for-bulk-setup) script or ['4.2 - Manual setting (example for servers in the DMZ)'](#42---manual-setting-example-for-servers-in-the-dmz) and clicking and clicking....(Manual settings are suitable for servers in the DMZ).

&nbsp;
## 4.1 Batch script for bulk setup
- Display SID for group '**WMI-monitoring-Group**'. The Active Directory PowerShell module needs to be installed. <br>

```
Install-WindowsFeature -Name "RSAT-AD-PowerShell" -IncludeAllSubFeature
```
```
Get-ADGroup -Identity "WMI-monitoring-Group" | Select-Object Name, SID
```

![image](https://user-images.githubusercontent.com/115627299/216953024-4a4ca456-be1e-4f67-aec8-e845ea02904c.png)

- We will save the following script on the computer '**Remote-Add-WMI-permissions.ps1**' from which you will run it. The computer must be part of Active Directory. **We will change the '$sid = "S-1-5-21-2497564049-359472916-1571357390-2602"' in the following script.**

```
# -------------------------------------------------------------------------------------------------- 
# SCRIPT TO REMOTELY ADD RIGHTS TO WMI
#
# 1. Create a "computers.txt" file and add the IP/FQDN of the remote servers. Each server on a
#    separate line
# 2. Run the script under a user who has Administrators rights on remote servers
# 3. Change by changing '$sid'. The SID is the group SID from '2. Creating a GPO to distribute
#    permissions'
# -------------------------------------------------------------------------------------------------- 


function get-sid
{
Param (
$DSIdentity
)
$ID = new-object System.Security.Principal.NTAccount($DSIdentity)
return $ID.Translate( [System.Security.Principal.SecurityIdentifier] ).toString()
}

# Change SID !!!!!!!
$sid = "S-1-5-21-2497564049-359472916-1571357390-2602"


# An example of using SDDL permissions------------------------------------- --------------
# http://msdn.microsoft.com/en-us/library/cc223511%28v=prot.20%29.aspx
# http://msdn.microsoft.com/en-us/library/windows/desktop/aa374928%28v=vs.85%29.aspx
$SDDL = "A;CI;CCWP;;;$sid"
$computers = Get-Content "computers.txt"
foreach ($strcomputer in $computers)
{
    $security = Get-WmiObject -ComputerName $strcomputer -Namespace root -Class __SystemSecurity
    $converter = new-object system.management.ManagementClass Win32_SecurityDescriptorHelper
    $binarySD = @($null)
    $result = $security.PsBase.InvokeMethod("GetSD",$binarySD)
    $outsddl = $converter.BinarySDToSDDL($binarySD[0])
    $newSDDL = $outsddl.SDDL += "(" + $SDDL + ")"
    $WMIbinarySD = $converter.SDDLToBinarySD($newSDDL)
    $WMIconvertedPermissions = ,$WMIbinarySD.BinarySD
    $result = $security.PsBase.InvokeMethod("SetSD",$WMIconvertedPermissions)
}
```

- Run PowerShell as a user who is Administrator on remote servers. <br>
![image](https://user-images.githubusercontent.com/115627299/217007096-9bcb9c59-2ae8-43ef-aa4f-8760069319a9.png)
![image](https://user-images.githubusercontent.com/115627299/216955083-3070a681-9b2b-49df-8c3d-4139c7de2384.png)

- Create a "**computers.txt**" file and add the IP/FQDN of the remote servers. Each server on a separate line. <br>
![image](https://user-images.githubusercontent.com/115627299/216955701-788ef1a3-5edf-4470-a3d2-6cd8c068a85d.png)

- Run the script. If everything is OK, the script will not display any critical messages. In case of problems, start in small doses. <br>
![image](https://user-images.githubusercontent.com/115627299/216956883-5c1ffaa2-ded9-4804-9359-d700f0ef7adf.png)


&nbsp;
## 4.2 - Manual setting (example for servers in the DMZ)
> I use manual settings for testing or servers in the DMZ.
- Open MMC 'Computer Management -> Services and Applications -> WMI Control (Properties)'<br>:
![image](https://user-images.githubusercontent.com/115627299/216769253-97d98b12-5b5d-4f91-a232-67c707416dfd.png)

- Security tab -> Root -> Security. Adding the Group from paragraph 1. and enabling 'Remote Enable'.
![image](https://user-images.githubusercontent.com/115627299/216769430-6926070c-5575-4e29-ade7-0b0e848360c8.png)

- Applies to 'The namespace and subnamespaces'<br>
![image](https://user-images.githubusercontent.com/115627299/216769667-b03564f6-67b1-4cea-9e18-563a67a470ba.png)

> The 'WMI-monitoring-Group' Group now has remote access rights to the entire WMI 'Root' and all namespace and subnamespaces.


<!-- 5. LINUX DEBIAN --------------------------------------------------------------------------------------------------------------------->

&nbsp;
# 5. Installing wmic_server on Debian 11 (WMI monitoring from Linux server)

- Update/Upgrade Debian
```
apt update
```
```
apt upgrade
```
> After the upgrade, a reboot is ideal :)
- Download wmic_server
```
cd /opt/
mkdir wmicserver
chown 775 wmicserver/
cd wmicserver
```
```
apt install git
git clone https://github.com/cesbit/aiowmi
```

- Python 3.7 and above is required. On Debian 11.6 is Python 3.9.2
```
python3 --version
```

- wmic_server will require the following python modules.
> aiowmi>=0.1.17; Flask>=2.0.3 ;PyYAML>=6.0
```
apt install pip
```

- Install python modules
```
pip3 install Flask
pip3 install PyYAML
pip3 install aiowmi
pip3 install gunicorn
```

- List/Test version for required modules
```
pip3 list | egrep "aiowmi|Flask|PyYAML|gunicorn"
```

```
cd /opt/wmicserver/aiowmi/contrib/wmic_server
cp wmic_server.yaml.sample wmic_server.yaml
```
```
nano wmic_server.yaml
```

- Edit and change '**logon name/password**' to the user from paragraph [1. Creating a group and an account in Active Directory](#1-creating-a-group-and-an-account-in-active-directory-for-windows-monitoring-using-wmi)

Comment out unused settings. Change tokens for 'user1' (**Attention** - do not use special characters in the token. Only lowercase letters and numbers worked for me). Token is the password with which the script 'check_wmi_os_security' and 'wmic_server' will communicate.<br>
![image](https://user-images.githubusercontent.com/115627299/216815842-2b8b9dfb-faac-4632-a409-cb015033e6fc.png)


&nbsp;
## 5.1 - Functionality testing of wmic_server
- Testing 'wmic_server' startup. Run 'wmic_server' and in the second window verify 'netstat' if it is listening on **127.0.0.1:2313**
```
nice gunicorn -b 127.0.0.1:2313 --pythonpath /opt/wmicserver/aiowmi --threads 1 wmic_server:app
```
```
netstat -nl | grep 2313
```
![image](https://user-images.githubusercontent.com/115627299/216770641-54aa9bfb-b205-4833-ab6a-4959d14f9219.png)
![image](https://user-images.githubusercontent.com/115627299/216770691-c160d5be-20cd-42a9-ab83-2a75178eef11.png)

- First testing of the WMI query using the script that is part of the wmic_server. Change the FQDN to the servers that have the previous paragraph 1. to 4. implemented '**-h srv01.test.local**'.
```
apt install curl
```
```
cd /opt/wmicserver/aiowmi/contrib/wmic_server
```
```
./wmic_client.sh -i user1 -t YOURtokenSecret159 -h srv01.test.local -q "SELECT * FROM Win32_UTCTime"
```
> If everything is OK, the script returns the data <br>
![image](https://user-images.githubusercontent.com/115627299/216770877-75fe8171-3c5b-4a57-b290-d5a32ec7f754.png)

&nbsp;
## 5.2 - Configuring wmic_server to run as a service
- Return to the 'wmic_server' window and exit the test instance **CTRL+C**
![image](https://user-images.githubusercontent.com/115627299/216811166-cecb5629-997d-4158-a5c0-91b08975cfe2.png)

- Copying the source configuration file
```
cd /opt/wmicserver/aiowmi/contrib/wmic_server/
cp wmic_server.service.sample /etc/systemd/system/wmic_server.service
```
- Remove executable permission bits
```
chmod -x /etc/systemd/system/wmic_server.service
```

- Edit the source configuration file
```
nano /etc/systemd/system/wmic_server.service
```
- Comment out the line starting 'ExecStart=nice gunicorn' and copy the following:
```
ExecStart=nice gunicorn -b 127.0.0.1:2313 --pythonpath /opt/wmicserver/aiowmi,/opt/wmicserver/aiowmi/contrib/wmic_server --threads 4 --workers=8  wmic_server:app
```
![image](https://user-images.githubusercontent.com/115627299/216811702-5d6d1800-bb4a-4c33-82fc-9f2bb8c8b4a2.png)

> Here it is possible to increase the **performance** for 'wmic_server'. I personally use '**--threads 4 --workers=8**' for about 60 servers. More information for example here https://medium.com/building-the-system/gunicorn-3-means-of-concurrency-efbb547674b7

- Systemctl configuration
```
systemctl daemon-reload
systemctl enable wmic_server
systemctl start wmic_server
systemctl status wmic_server
```
![image](https://user-images.githubusercontent.com/115627299/216811888-36c59645-4099-4b7b-8652-bf8f8bd02234.png)

- Checking if 'wmic_sercver' is listening on localhost on TCP/2313
```
netstat -lna | grep 2313
```
> **SECURITY:**
'wmic_server' communicates over **HTTP**. If the 'wmic_server' server is running on the same server as the monitoring engine (example Centreon, Nagios, Icinga etc.), I personally do not need an **SSL** certificate. The server listens only on localhost, low probability of abuse. If 'wmic_server' will run on a separate server, it is ideal to implement an SSL certificate and set a personal firewall on the source IP and TCP/2313. [More information here](https://github.com/cesbit/aiowmi/tree/main/contrib/wmic_server#starting-the-sever)

- Restart the server and verify correct functionality
```
journalctl -p 4 -xb
```


<!-- 6. 'check_wmi_os_security' ------------------------------------------------------------------------------------------------------------->
&nbsp;
# 6. Implementation of 'check_wmi_os_security'

- Install/Download 'check_wmi_os_security'.
```
cd /opt/
```
```
git clone https://github.com/Louda-Jan/check_wmi_os_security
```
```
cd check_wmi_os_security/
chmod +x check_wmi_os_security.py 
```

- Check the user variables. <br>
```
nano check_wmi_os_security.py
```
![image](https://user-images.githubusercontent.com/115627299/217235738-2a498722-2219-4801-b7ba-47c6b63e546c.png)

- First check. Use the token you used when editing **wmic_server.yaml**. Change the FQDN to your server.
```
./check_wmi_os_security.py --user=user1 --token=YOURtokenSecret159 --host=srv01.test.local --query=os
```
- Output if everything is OK :smiley:<br>&nbsp;
![image](https://user-images.githubusercontent.com/115627299/217014756-06e5d2f8-388d-471c-bf34-615cfaa8138a.png)


> - If 'check_wmi_os_security' does not return correct output check:
>   - [Firewall rules](#3-firewall-rules-allowing-wmi-from-the-monitoring-engine-server) on the remote server (it is possible to turn off the firewall for a while)
>   - If the 'token' is entered correctly. The 'wmic_server' service needs to be restarted when changing the token in 'wmic_server.yaml'
>   - Is FQND correct. Try dig/ping if DNS is OK
>   - Are the [permissions for WMI](#4-setting-wmi-permissions-on-a-windows-servers) on the target Windows server set correctly?
>   - Is the WMi monitoring user a member of local groups (BUILTIN\Performance Monitor Users; BUILTIN\Event Log Readers; BUILTIN\Distributed COM Users) on the target Windows server?

&nbsp;
## 7. GPO - Advanced audit configuration for a security log
For more detailed security logging, it is necessary to set advanced auditing for Security log using GPO. The security log then contains much more information about the OS.

&nbsp;
- Security Log size
GPO:  **Computer Configuration/Administrative Templates/Windows Components/Event Log Service/Security**
Item: specify the Maximum log size (KB) **600128**                                                     

&nbsp;
![image](https://user-images.githubusercontent.com/115627299/217188596-1c40ae03-936e-4f62-bb04-b36699ba8477.png)


- Audit for Security Logs
GPO:  **Computer Configuration/Security Settings/Advanced Audit Configuration/Object Access**
Item: (Advanced Audit Configuration)

> Configuration recommendations based on Microsoft Base Line https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-security-configuration-framework/windows-security-baselines and experience. For example, "Object Access;Audit Kernel Object;Success and Failure" will write you an > event when someone performs a memory dump to find out the RDP passwords (they are there in clear text).

&nbsp;
![image](https://user-images.githubusercontent.com/115627299/217188636-af76b4cc-a444-41b6-8353-67211a55d071.png)


&nbsp;
**Settings of individual items separated by ';'. It is possible to import the list into, for example, LibreOffice.**
```
Policy Path;Policy Setting Name;Setting
Account Logon;Audit Credential Validation;Success and Failure
Account Logon;Audit Kerberos Authentication Service;
Account Logon;Audit Kerberos Service Ticket Operations;
Account Logon;Audit Other Account Logon Events;Success and Failure
Account Management;Audit Application Group Management;
Account Management;Audit Computer Account Management;Success and Failure
Account Management;Audit Distribution Group Management;
Account Management;Audit Other Account Management Events;Success and Failure
Account Management;Audit Security Group Management;Success and Failure
Account Management;Audit User Account Management;Success and Failure
Detailed Tracking;Audit DPAPI Activity;Success and Failure
Detailed Tracking;Audit PNP Activity;Success
Detailed Tracking;Audit Process Creation;Success
Detailed Tracking;Audit Process Termination;
Detailed Tracking;Audit RPC Events;
Detailed Tracking;Audit Token Right Adjusted;
DS Access;Audit Detailed Directory Service Replication;
DS Access;Audit Directory Service Access;
DS Access;Audit Directory Service Changes;
DS Access;Audit Directory Service Replication;
Global Object Access Auditing;File system;
Global Object Access Auditing;Registry;
Logon/Logoff;Audit Account Lockout;Failure
Logon/Logoff;Audit Group Membership;Success
Logon/Logoff;Audit IPsec Extended Mode;
Logon/Logoff;Audit IPsec Main Mode;
Logon/Logoff;Audit IPsec Quick Mode;
Logon/Logoff;Audit Logoff;Success
Logon/Logoff;Audit Logon;Success and Failure
Logon/Logoff;Audit Network Policy Server;
Logon/Logoff;Audit Other Logon/Logoff Events;Success and Failure
Logon/Logoff;Audit Special Logon;Success
Logon/Logoff;Audit User / Device Claims;
Object Access;Audit Application Generated;
Object Access;Audit Central Access Policy Staging;
Object Access;Audit Certification Services;
Object Access;Audit Detailed File Share;Failure
Object Access;Audit File Share;Success and Failure
Object Access;Audit File System;
Object Access;Audit Filtering Platform Connection;
Object Access;Audit Filtering Platform Packet Drop;
Object Access;Audit Handle Manipulation;
Object Access;Audit Kernel Object;Success and Failure
Object Access;Audit Other Object Access Events;Success and Failure
Object Access;Audit Registry;
Object Access;Audit Removable Storage;Success and Failure
Object Access;Audit SAM;
Policy Change;Audit Audit Policy Change;Success and Failure
Policy Change;Audit Authentication Policy Change;Success and Failure
Policy Change;Audit Authorization Policy Change;Success and Failure
Policy Change;Audit Filtering Platform Policy Change;
Policy Change;Audit MPSSVC Rule-Level Policy Change;Success and Failure
Policy Change;Audit Other Policy Change Events;Failure
Privilege Use;Audit Non Sensitive Privilege Use;
Privilege Use;Audit Other Privilege Use Events;
Privilege Use;Audit Sensitive Privilege Use;Success and Failure
System;Audit IPsec Driver;
System;Audit Other System Events;Success and Failure
System;Audit Security State Change;Success
System;Audit Security System Extension;Success
System;Audit System Integrity;Success and Failure
```
&nbsp;
&nbsp;
<sub>English is terrible but I hope you can do it :)</sub>
