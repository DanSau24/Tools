************************************************
----- LDAP_Ldaps_Checker powershell script -----
************************************************

This is a script for testing LDAP | LDAPS connections that will help us determine whether the issue is on the code side or related to the network, certificate,ciphers,Tls, ports, DNS, etc.
You can run this from Client workstations part of the Domain. You can either Powershell ISE or run it as .ps1 script. This will spwan .tls and .log file.


What does this script do?
==========================
1	Prompts for the type of connection to test: LDAP (port 389) | LDAPS (port 636)
2	Requests credentials:
A. Domain username
B. Domain
C. Password (entered via PowerShell’s credential prompt for security reasons)
3	Starts a NETSH trace to capture network traffic.
4	Tests the connection and retrieves user data from the directory using:  Get-ADUser -Identity username -Server -Domain -Credential   and then System.DirectoryServices.DirectoryEntry
5	Checks ports by performing a connection test and inspecting the local firewall state. If ports are blocked, it prompts the user to enable them.
6	Runs network and DNS tests.
7	[For LDAPS] Displays the current certificate used for the connection.
8	[For LDAPS] Fetches the list of enabled ciphers on the system.
9	[For LDAPS] If the OS version is older than Windows 10 or Windows Server 2022, it retrieves the list of TLS versions from the registry and their state (enabled/disabled).
If the OS is modern, it provides the official Microsoft link where users can check the default TLS versions, as they are no longer configured in the registry.
10	Asks the user if they want to query additional data from the LDAP server (e.g., user or computer objects).
11	Terminates the NETSH (.etl trace).
12	Generates a log file with the results.


![image](https://github.com/user-attachments/assets/8fffac6f-aab3-42ab-8a2c-331d5c64c0db)


![image](https://github.com/user-attachments/assets/ca8fd607-04a1-48d0-8fe6-4a7b29f28b33)


![image](https://github.com/user-attachments/assets/0539b906-4877-4125-8971-8a6658faabf0)


![image](https://github.com/user-attachments/assets/d05de318-da5a-4878-a232-24ba1a55f860)

![image](https://github.com/user-attachments/assets/070639d6-6327-4ef2-b3dd-3f5eb6bbb8ed)

![image](https://github.com/user-attachments/assets/36583777-8e0f-4e1f-bf5e-33006423e1d8)

![image](https://github.com/user-attachments/assets/f0ba727a-bab9-4abe-8f68-320a89bae128)


This will  generate both a .etl trace and logfile 
![image](https://github.com/user-attachments/assets/2cd0d1a1-76d7-4256-8b9c-f862a9882c3f)
![image](https://github.com/user-attachments/assets/0743137e-b334-4160-952e-33cc8122a64b)
We can use netmon UI to look into the trace.







