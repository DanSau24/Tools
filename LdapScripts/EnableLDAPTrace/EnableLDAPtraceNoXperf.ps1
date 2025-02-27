#This requires to be ran as administrator
#This assumes XPerf is in the same directory or is available in the current executable search path
#This also assumes you know which executable to add to the registry; modify $name accordingly
$name = "w3wp.exe" #Rename this to the process' executable name where the code runs
$keysToRemove = New-Object System.Collections.ArrayList
$keysToRemoveAdsi = New-Object System.Collections.ArrayList
 
$regKeyBase = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
$regKeyLdap = $regKeyBase.CreateSubKey("System\CurrentControlSet\Services\ldap\Tracing", $true)
$regKeyAdsi = $regKeyBase.CreateSubKey("System\CurrentControlSet\Services\adsi\Tracing", $true)
 
 
    #ldap
    try
    {
        #Try to open it first...don't want to delete it later if it was already there and we didn't have to create it
        $regKeyLdap.OpenSubKey($name).Dispose()
    }
    catch
    {
        $regKeyLdap.CreateSubKey($name).Dispose()
        [void]$keysToRemove.Add($name)
    }
    #adsi
    try
    {
        #Try to open it first...don't want to delete it later if it was already there and we didn't have to create it
        $regKeyAdsi.OpenSubKey($name).Dispose()
    }
    catch
    {
        $regKeyAdsi.CreateSubKey($name).Dispose()
        [void]$keysToRemoveAdsi.Add($name)
    }
#I'd recommend having them upload $userFilename, $authFilename, and $outputFilename    
 
$kernelFileName = "kernel.etl" #Change this if you want to use something other than the current directory
$userFilename = "user.etl" #Change this if you want to use something other than the current directory
$outputFilename = "ldap_adsi.etl"#Change this if you want to use something other than the current directory
$authFilename = ".\ds_adsi.etl"#Change this if you want to use something other than the current directory
$userLoggerName = "LDAPADSILogger"
$authLoggername = "authLoggersForLdapTrace"
 

#Start auth loggers
logman create trace "$authLoggername" -ow -o "$authFilename" -p "Microsoft-Windows-ADSI" 0xffffffffffffffff 0xff -nb 64 256 -bs 8192 -mode Circular -f bincirc -max 4096 -ets
logman update trace "$authLoggername" -p "Microsoft-Windows-LDAP-Client" 0x1FFFFFF3 0xff -ets
logman update trace "$authLoggername" -p "Microsoft-Windows-DNS-Client" 0xffffffffffffffff 0xff -ets
logman update trace "$authLoggername" -p "{BBA3ADD2-C229-4CDB-AE2B-57EB6966B0C4}" 0xffffffffffffffff 0xff -ets
logman update trace "$authLoggername" -p "{6B510852-3583-4E2D-AFFE-A67F9F223438}" 0xffffffffffffffff 0xff -ets
logman update trace "$authLoggername" -p "{FACB33C4-4513-4C38-AD1E-57C1F6828FC0}" 0xffffffffffffffff 0xff -ets
logman update trace "$authLoggername" -p "{5AF52B0D-E633-4EAD-828A-4B85B8DAAC2B}" 0xffffffffffffffff 0xff -ets
logman update trace "$authLoggername" -p "{5BBB6C18-AA45-49B1-A15F-085F7ED0AA90}" 0xffffffffffffffff 0xff -ets
logman update trace "$authLoggername" -p "Microsoft-Windows-Security-Kerberos" 0xffffffffffffffff 0xff -ets
logman update trace "$authLoggername" -p "Microsoft-Windows-Security-Netlogon" 0xffffffffffffffff 0xff -ets
logman update trace "$authLoggername" -p "{44492B72-A8E2-4F20-B0AE-F1D437657C92}" 0xffffffffffffffff 0xff -ets
 
Read-Host -Prompt "Press enter after reproducing issue"
 
#Stop auth logger
logman stop "$authLoggername" -ets
#Stop user logger
xperf -stop $userLoggerName
#Stop kernel logger
xperf -stop
#Merge kernel and user loggers
xperf -merge $kernelFileName $userFilename $outputFilename -compress
[System.IO.File]::Delete($userFilename)
 
#ldap
$keysToRemove | %{
    $regKeyLdap.DeleteSubKey($_)
}
#adsi
$keysToRemoveAdsi | %{
    $regKeyAdsi.DeleteSubkey($_)
}
$regKeyAdsi.Dispose()
$regKeyLdap.Dispose()
$regKeyBase.Dispose()
