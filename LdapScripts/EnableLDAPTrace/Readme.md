
LDAP & Kerberos Tracing Script
This PowerShell script captures LDAP traces along with Kerberos, ADSI, DNS, and other related events in a single run.

Instructions
Download the script and save it with a .ps1 extension.
Edit the script:
Open the file in a text editor.
Locate the 4th line and update the process name if w3wp.exe is not the correct target process.
Run the script in an elevated PowerShell window (Run as Administrator).
Follow the prompts:
The script will prompt you to reproduce the issue.
Perform the necessary actions to trigger the issue.
Capture the logs:
Once the issue occurs, return to the PowerShell window and press any key to stop tracing.
Ignore any errors that may appear.
Collect the logs:
A file named ds_adsi.etl will be generated.
Zip and upload the file for further analysis.
