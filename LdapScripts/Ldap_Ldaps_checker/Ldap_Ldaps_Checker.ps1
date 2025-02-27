# Generate the log file name with the current datetime
$logFile = if ($PSScriptRoot) { Join-Path -Path $PSScriptRoot -ChildPath "logfile_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').txt" } else { "logfile_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').txt" }


# Function to write logs
function Write-Log {
    param(
        [string]$logMessage
    )
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $logEntry = "$timestamp - $logMessage"
    # Ensure log file exists, create if not
    if (-not (Test-Path $logFile)) {
        New-Item -Path $logFile -ItemType File
    }
    Add-Content -Path $logFile -Value $logEntry
}

# Function to display output and log it
function Write-OutputAndLog {
    param(
        [string]$outputMessage
    )
    Write-Host $outputMessage
    Write-Log $outputMessage
}

# Log file path display to the user
Write-OutputAndLog "Log file will be saved at: $logFile"
Write-Log "Log file will be saved at: $logFile"



# Add a blank line below the header
Write-Host ""


Write-Host "------------------------------------------------------------" -ForegroundColor Green
Write-Host "**** LDAP|LDAPS CONNECTION CHECK ***" -ForegroundColor Green
Write-Host "------------------------------------------------------------" -ForegroundColor Green

# Prompt user to choose between LDAP and LDAPS connection
$connectionType = Read-Host "Do you want to test LDAP or LDAPS connection? (Enter 'LDAP' or 'LDAPS')"
Write-Host "User selected connection type: " -NoNewline; Write-Host $connectionType -ForegroundColor Cyan

if ($connectionType -ne "LDAP" -and $connectionType -ne "LDAPS") {
    Write-Host "Invalid input! Please enter either 'LDAP' or 'LDAPS'. Exiting script." -ForegroundColor Red
    exit
}

# Prompt for user credentials
$UserName = Read-Host "Enter the domain UserName (e.g. dansau)"
Write-Host "User entered UserName: " -NoNewline; Write-Host $UserName -ForegroundColor Cyan

$Domain = Read-Host "Enter the domain (e.g. dansau1.lab)"
Write-Host "User entered Domain: " -NoNewline; Write-Host $Domain -ForegroundColor Cyan

$FullUserName = "$Domain\$UserName"
Write-Host "Full UserName: " -NoNewline; Write-Host $FullUserName -ForegroundColor Cyan

$cred = Get-Credential -UserName $FullUserName -Message "Enter your password"



# Add a blank line below the header
Write-Host ""
Write-Host "------------------------------------------------------------" -ForegroundColor Green
Write-Host "****NETSH TRACE ***" -ForegroundColor Green
Write-Host "------------------------------------------------------------" -ForegroundColor Green

start Netsh trace


# Generate the trace file path dynamically in the same directory as the script
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$traceFile = if ($PSScriptRoot) { Join-Path -Path $PSScriptRoot -ChildPath "NETSHtrace_$timestamp.etl" } else { "NETSHtrace_$timestamp.etl" }


# Start network trace for LDAP authentication and queries
Write-Host "Starting network trace..." -ForegroundColor Yellow
netsh trace start capture=yes tracefile="$traceFile" maxsize=200 filemode=circular persistent=yes report=no overwrite=yes packettruncatebytes=512




# Connecting as Get-ADUser -Identity $UserName -Server $Domain -Credential $cred -Properties *

# Add a blank line below the header
Write-Host ""

Write-Host "------------------------------------------------------------" -ForegroundColor Green
Write-Host "**** LDAP CONNECTION TEST USING GET-ADUSER -identity username -server -domain -credential ***" -ForegroundColor Green
Write-Host "------------------------------------------------------------" -ForegroundColor Green

Write-Host "Retrieving information for user: " -NoNewline
Write-Host $UserName -ForegroundColor Cyan
Write-Host " in domain: " -NoNewline
Write-Host $Domain -ForegroundColor Cyan

$UserInfo = Get-ADUser -Identity $UserName -Server $Domain -Credential $cred -Properties *

if ($UserInfo) {
    Write-Host "`nUser Found! Displaying Fetched user data.." -ForegroundColor Green
    $UserInfo | Select-Object SamAccountName, Name, UserPrincipalName, Enabled, LastLogonDate, SID, MemberOf | Format-List

    # Save UserPrincipalName to a variable
    $userUPN = $UserInfo.UserPrincipalName
    Write-Host "UserPrincipalName (UPN): " -NoNewline
    Write-Host $userUPN -ForegroundColor Cyan

    if (-not $userUPN) {
        Write-Host "User has no UserPrincipalName (UPN). Proceeding to next instruction..." -ForegroundColor Yellow
    } else {
        Write-Host "UserPrincipalName has a value: " -NoNewline
        Write-Host $userUPN -ForegroundColor Cyan

        Write-Host "UserName has a value: " -NoNewline
        Write-Host $UserName -ForegroundColor Cyan

        $ldapServer = "LDAP://$Domain"
        Write-Host "LDAP Server: " -NoNewline
        Write-Host $ldapServer -ForegroundColor Cyan

        $port = if ($connectionType -eq "LDAPS") { 636 } else { 389 }
        Write-Host "Port: " -NoNewline
        Write-Host $port -ForegroundColor Cyan

        $password = $cred.GetNetworkCredential().Password
        # Further processing with $password
    }
}




Write-Host "" 

# Title (printed in default color)
Write-Host "*******************************************************************************" -ForegroundColor Green
Write-Host "**** CONNECTION TEST USING SYSTEM.DIRECTORYSERVICES.DIRECTORYENTRY ****" -ForegroundColor Green
Write-Host "*******************************************************************************" -ForegroundColor Green
Write-Host ""

# Determine if the connection should be LDAPS (Port 636) or LDAP (Port 389)
if ($ldapServer -match ":636") {
    # Create LDAPS connection with explicit SSL enforcement
    $ldapConnection = New-Object System.DirectoryServices.DirectoryEntry("${ldapServer}:${port}", $userUPN, $password)
    $ldapConnection.AuthenticationType = [System.DirectoryServices.AuthenticationTypes]::SecureSocketsLayer
    Write-Host "`nLDAPS Connection string: " -NoNewline
    Write-Host $ldapConnection.Path -ForegroundColor Cyan
} else {
    # Create LDAP connection (without SSL enforcement)
    $ldapConnection = New-Object System.DirectoryServices.DirectoryEntry("${ldapServer}:${port}", $userUPN, $password)
    Write-Host "`nLDAP Connection string: " -NoNewline
    Write-Host $ldapConnection.Path -ForegroundColor Cyan
}

# Test LDAPS or LDAP Connection
try {
    $ldapConnection.RefreshCache()

    if ($ldapConnection.Path -match ":636") {
        Write-Host "✔️ LDAPS connection successful to " -NoNewline
        Write-Host $ldapConnection.Path -ForegroundColor Cyan -NoNewline
        Write-Host " using " -NoNewline
        Write-Host $userUPN -ForegroundColor Cyan
        Write-Log "✔️ LDAPS connection successful to $($ldapConnection.Path) using $userName"
    } else {
        Write-Host "⚠️ WARNING: LDAP connection established, but it's not confirmed as LDAPS!"
        Write-Log "⚠️ WARNING: LDAP connection established, but it's not confirmed as LDAPS!"
    }

    Write-Host "Searching for user with UPN: " -NoNewline
    Write-Host $userUPN -ForegroundColor Cyan

    $Searcher = New-Object System.DirectoryServices.DirectorySearcher($ldapConnection)
    $Searcher.Filter = "(UserPrincipalName=$userUPN)"  # Use UPN in the filter
    $user = $Searcher.FindOne()

    if ($user -ne $null) {
        Write-Host "User '" -NoNewline
        Write-Host $UserName -ForegroundColor Cyan -NoNewline
        Write-Host "' found:"
        $user.Properties.PropertyNames | ForEach-Object {
            if ($user.Properties[$_].Count -gt 0) {
                Write-Host "$_ : " -NoNewline
                Write-Host $user.Properties[$_] -ForegroundColor Cyan
                Write-Log "User '$UserName' found:"
            }
        }
    } else {
        Write-Host "User '" -NoNewline
        Write-Host $UserName -ForegroundColor Cyan -NoNewline
        Write-Host "' not found."
        Write-Log "User '$UserName' not found."
    }
}
catch {
    Write-Host "❌ Error: " -NoNewline
    Write-Host $_ -ForegroundColor Red
    Write-Log "❌ Error: $_"
}












# Function to test outbound connection


# Header in default color (white)
Write-Host ""
Write-Host "*************************************************************"-ForegroundColor Green
Write-Host "**** TESTING PORTS ***" -ForegroundColor Green


function Test-OutboundConnection {
    param(
        [string]$HostName,
        [int]$Port
    )

    $connectionTest = Test-NetConnection -ComputerName $HostName -Port $Port -InformationLevel Quiet
    return $connectionTest
}

# Function to enable outbound firewall rule for a port
function Enable-OutboundFirewallRule {
    param(
        [string]$DisplayName,
        [int]$Port
    )

    # Display custom text in default (white) color and only the port variable in cyan.
    Write-Host "Enabling firewall rule for outbound connection on port " -NoNewline
    Write-Host $Port -ForegroundColor Cyan -NoNewline
    Write-Host "..."
    
    Write-Log "Enabling firewall rule for outbound connection on port $Port"
    New-NetFirewallRule -DisplayName $DisplayName -Protocol TCP -RemotePort $Port -Action Allow -Direction Outbound
}


# Function to display certificate information (only for LDAPS)
if ($connectionType -eq "ldaps") {
    Write-Host "**** FETCHING THE CERTIFICATE USED FOR LDAPS ***" -ForegroundColor Green
}

function Get-CertificateInfo {
    param(
        [string]$HostName,
        [int]$Port
    )

    # Display retrieving message with only the variable parts in cyan
    Write-Host "`nRetrieving certificate information from " -NoNewline
    Write-Host $HostName -ForegroundColor Cyan -NoNewline
    Write-Host " on port " -NoNewline
    Write-Host $Port -ForegroundColor Cyan -NoNewline
    Write-Host "..."

    Write-Log "Retrieving certificate information from $HostName on port $Port"

    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient($HostName, $Port)
        $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, { $true })
        $sslStream.AuthenticateAsClient($HostName)

        $certificate = $sslStream.RemoteCertificate

        Write-Host "`nCertificate Information:"

        Write-Host "Subject: " -NoNewline
        Write-Host $certificate.Subject -ForegroundColor Cyan

        Write-Host "Issuer: " -NoNewline
        Write-Host $certificate.Issuer -ForegroundColor Cyan

        Write-Host "Thumbprint: " -NoNewline
        Write-Host $certificate.GetCertHashString() -ForegroundColor Cyan

        Write-Host "Valid From: " -NoNewline
        Write-Host $certificate.GetEffectiveDateString() -ForegroundColor Cyan

        Write-Host "Valid Until: " -NoNewline
        Write-Host $certificate.GetExpirationDateString() -ForegroundColor Cyan

        Write-Host "Signature Algorithm: " -NoNewline
        Write-Host $certificate.SignatureAlgorithm.FriendlyName -ForegroundColor Cyan

        Write-Host "Friendly Name: " -NoNewline
        Write-Host $certificate.PublicKey.Oid.FriendlyName -ForegroundColor Cyan

        $tcpClient.Close()

        Write-Log "Certificate Information: Subject=$($certificate.Subject), Issuer=$($certificate.Issuer), Thumbprint=$($certificate.GetCertHashString()), ValidFrom=$($certificate.GetEffectiveDateString()), ValidUntil=$($certificate.GetExpirationDateString()), SignatureAlgorithm=$($certificate.SignatureAlgorithm.FriendlyName), FriendlyName=$($certificate.PublicKey.Oid.FriendlyName)"
    } catch {
        Write-Host "Failed to retrieve certificate information from " -NoNewline
        Write-Host $HostName -ForegroundColor Cyan -NoNewline
        Write-Host " on port " -NoNewline
        Write-Host $Port -ForegroundColor Cyan
        Write-Log "Failed to retrieve certificate information from $HostName on port $Port."
    }
}




# Header in default (white) color
Write-Host "**** TESTING NETWORK CONNECTION***" -ForegroundColor Green
Write-Host "*************************************************************" -ForegroundColor Green

# Test outbound connection for LDAP/LDAPS (depending on user selection)
$port = if ($connectionType -eq "LDAPS") { 636 } else { 389 }

# Display outbound connection test message with variables in cyan
Write-Host "`nTesting outbound connection to " -NoNewline
Write-Host $connectionType -ForegroundColor Cyan -NoNewline
Write-Host " (Port " -NoNewline
Write-Host $port -ForegroundColor Cyan -NoNewline
Write-Host ")..."
Write-Log "Testing outbound connection to $connectionType (Port $port)..."

$ldapOutboundTest = Test-OutboundConnection -HostName "dc.$Domain" -Port $port

# Display results for outbound connection with variable parts in cyan
if ($ldapOutboundTest) {
    Write-Host ""
    Write-Host "Result: " -NoNewline
    Write-Host $connectionType -ForegroundColor Cyan -NoNewline
    Write-Host " port " -NoNewline
    Write-Host $port -ForegroundColor Cyan -NoNewline
    Write-Host " is OPEN for outbound connections."
    Write-Log "$connectionType port $port is OPEN for outbound connections."
    
    # Retrieve certificate info if LDAPS is selected
    if ($connectionType -eq "LDAPS") {
        Get-CertificateInfo -HostName "dc.$Domain" -Port 636
    }
} else {
    Write-Host ""
    Write-Host "Result: " -NoNewline
    Write-Host $connectionType -ForegroundColor Cyan -NoNewline
    Write-Host " port " -NoNewline
    Write-Host $port -ForegroundColor Cyan -NoNewline
    Write-Host " is CLOSED for outbound connections!"
    Write-Log "$connectionType port $port is CLOSED for outbound connections!"
    $enablePort = Read-Host "Do you want to enable the outbound $connectionType firewall rule? (Yes/No)"
    if ($enablePort -eq "Yes") {
        Enable-OutboundFirewallRule -DisplayName "Allow Outbound $connectionType Port $port" -Port $port
    }
}

# Check firewall profiles status
Write-Host "`nChecking Firewall Profiles Status..."-ForegroundColor Green
Write-Log "Checking Firewall Profiles Status..." 
Get-NetFirewallProfile | Select-Object Name, Enabled | Format-Table -AutoSize

# Check LDAP name resolution
Write-Host "`nChecking Name Resolution for LDAP Server: _ldap._tcp.dc._msdcs." -NoNewline
Write-Host $Domain -ForegroundColor Cyan
Write-Log "Checking Name Resolution for LDAP Server: _ldap._tcp.dc._msdcs.$Domain"
$ldapResolution = Resolve-DnsName -Type SRV "_ldap._tcp.dc._msdcs.$Domain" -ErrorAction SilentlyContinue
if ($ldapResolution) {
    Write-Host "LDAP Server Name Resolution Successful!"
    Write-Log "LDAP Server Name Resolution Successful!"
    $ldapResolution | Format-Table -AutoSize
} else {
    Write-Host "LDAP Server Name Resolution Failed!"
    Write-Log "LDAP Server Name Resolution Failed!"
}

# Check ping response to LDAP server
Write-Host "`nChecking Ping Response to LDAP Server..."
Write-Log "Checking Ping Response to LDAP Server..."
$pingResult = Test-Connection -ComputerName $Domain -Count 2 -ErrorAction SilentlyContinue
if ($pingResult) {
    Write-Host "LDAP Server is Reachable via Ping!" -ForegroundColor Cyan
    Write-Log "LDAP Server is Reachable via Ping!"
    $pingResult | Format-Table -AutoSize
} else {
    Write-Host "LDAP Server is NOT Reachable!" -ForegroundColor Red
    Write-Log "LDAP Server is NOT Reachable!"
}





#functions to check TLS and Ciphers of Windows.




# ================================
# Function: Get Full OS Information
# ================================
function Get-OSInfo {
    $os = Get-CimInstance -Class Win32_OperatingSystem
    $version = [version]$os.Version
    $osInfo = @{
        Caption = $os.Caption
        Version = $version
    }
    Write-Host "`n=== OS Information ===" -ForegroundColor Green
    Write-Host "$($os.Caption) - Version: $version"
    Write-Host "`nYou can check list of OS and versions here: https://learn.microsoft.com/en-us/windows/win32/sysinfo/operating-system-version?utm_source=chatgpt.com" -ForegroundColor Yellow
    return $osInfo
}

# ================================
# Function: Get TLS/SSL Versions from Registry
# ================================
function Get-TLSVersionsFromRegistry {
    Write-Host "`n=== TLS/SSL Versions in Registry ===" -ForegroundColor Green
    $tlsRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
    if (Test-Path $tlsRegistryPath) {
        $tlsEntries = Get-ChildItem -Path $tlsRegistryPath -ErrorAction SilentlyContinue
        if ($tlsEntries) {
            foreach ($entry in $tlsEntries) {
                $clientPath = "$tlsRegistryPath\$($entry.PSChildName)\Client"
                $serverPath = "$tlsRegistryPath\$($entry.PSChildName)\Server"
                if (Test-Path $clientPath) {
                    $clientProp = Get-ItemProperty -Path $clientPath -Name 'Enabled' -ErrorAction SilentlyContinue
                    $clientStatus = if ($clientProp.Enabled -eq 1) { "Enabled" } else { "Disabled" }
                } else {
                    $clientStatus = "Not Found"
                }
                if (Test-Path $serverPath) {
                    $serverProp = Get-ItemProperty -Path $serverPath -Name 'Enabled' -ErrorAction SilentlyContinue
                    $serverStatus = if ($serverProp.Enabled -eq 1) { "Enabled" } else { "Disabled" }
                } else {
                    $serverStatus = "Not Found"
                }
                Write-Host "$($entry.PSChildName): Client - $clientStatus, Server - $serverStatus"
            }
        } else {
            Write-Host "No TLS/SSL protocols found in registry."
        }
    } else {
        Write-Host "TLS registry path not found."
    }
}

# ================================
# Function: Get Cipher Suites from Registry
# ================================
function Get-CipherSuitesFromRegistry {
    Write-Host "`n=== Cipher Suites from Registry ===" -ForegroundColor Green
    $cipherSuitesPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002"
    if (Test-Path $cipherSuitesPath) {
        $cipherSuites = Get-ItemProperty -Path $cipherSuitesPath -Name 'Functions' -ErrorAction SilentlyContinue
        if ($cipherSuites.Functions) {
            $cipherSuitesList = $cipherSuites.Functions -split ','
            foreach ($cipher in $cipherSuitesList) {
                Write-Host "Cipher Suite: $cipher"
            }
        } else {
            Write-Host "No cipher suites found in registry."
        }
    } else {
        Write-Host "Cipher suites registry path not found."
    }
}

# ================================
# Function: Get Cipher Suites from OS (Modern Systems)
# ================================
function Get-CipherSuitesFromOS {
    Write-Host "`n=== Cipher Suites from OS (Get-TlsCipherSuite) ===" -ForegroundColor Green
    $cipherSuites = Get-TlsCipherSuite -ErrorAction SilentlyContinue
    if ($cipherSuites) {
        $cipherSuites | Select-Object Name, Protocols | Format-Table -AutoSize
    } else {
        Write-Host "No cipher suites found."
    }
}


if ($connectionType -eq "ldaps") {

Write-Host "*************************************************************" -ForegroundColor Green
Write-Host "**** FETCHING TLS & CIPHERS ***" -ForegroundColor Green
Write-Host "*************************************************************" -ForegroundColor Green



$osInfo = Get-OSInfo
$windows_version = $osInfo.Version

# Define threshold version: Modern if version >= 10.0.15063 (Windows Server 2016)
$modernThreshold = [version]"10.0.15063"

if ($windows_version -lt $modernThreshold) {
    Get-TLSVersionsFromRegistry
    Get-CipherSuitesFromRegistry
} 
else {
 
    Get-CipherSuitesFromOS
    Write-Host "`nSupported TLS versions for this O.S.,refer to:" -ForegroundColor Green
    Write-Host "https://learn.microsoft.com/en-us/windows/win32/secauthn/protocols-in-tls-ssl--schannel-ssp-" -ForegroundColor Yellow
}


}






Write-Host ""
# Header in green
Write-Host "*************************************************************" -ForegroundColor Green
Write-Host "**** SEARCH LDAP DIRECTORY ***" -ForegroundColor Green
Write-Host "*************************************************************" -ForegroundColor Green

# Prompt user for additional searches
while ($true) {
    # Display prompt in white
    Write-Host "`nWould you like to search for another object? [ YES |  NO  ]" -NoNewline
    $continueSearch = Read-Host
   
   # Write-Host "`nWould you like to search for another object?" 
  #  $continueSearch = Read-Host "Enter 'Yes' to continue or 'No' to exit"
    Write-Log "User decision to continue search: $continueSearch"

    if ($continueSearch -ne "Yes") {
        Write-Host "`nExiting script...!" -ForegroundColor Yellow
        Write-Log "Exiting script as User requested!"
        break
    }

    # Display options
    Write-Host "`nSelect object type to search:" -ForegroundColor White
    Write-Host "1. Users" -ForegroundColor Yellow
    Write-Host "2. Computers" -ForegroundColor Yellow
    $choice = Read-Host "Enter the object type you want to search [ 1 | 2 ]..."  -ForegroundColor Yellow

    # Initialize search result as $null for each iteration to avoid previous data interference
    $searchResult = $null

    if ($choice -eq "1") {
        $searchUser = Read-Host "Enter the username to search"   -ForegroundColor Yellow
        Write-Log "Searching for user: $searchUser"
        $searchResult = Get-ADUser -Identity $searchUser -Server $Domain -Credential $cred -Properties *

        if ($searchResult) {
            Write-Host "`nSearch Result for User:" -ForegroundColor Cyan
            Write-Log "`nSearch Result for User:"
            $searchResult | Format-List
            Write-Log "Search result: $($searchResult | Format-List | Out-String)"
        } else {
            Write-Host "`nUser '$searchUser' does not exist in DC." -ForegroundColor Red
            Write-Log "`nUser '$searchUser' does not exist in DC."     -ForegroundColor Red
        }
    } elseif ($choice -eq "2") {
        $searchComputer = Read-Host "Enter the computer name to search" -ForegroundColor Yellow
        Write-Log "Searching for computer: $searchComputer"
        $searchResult = Get-ADComputer -Identity $searchComputer -Server $Domain -Credential $cred -Properties *

        if ($searchResult) {
            Write-Host "`nSearch Result for Computer:" -ForegroundColor Cyan
            Write-Log "`nSearch Result for Computer:"
            $searchResult | Format-List
            Write-Log "Search result: $($searchResult | Format-List | Out-String)"
        } else {
            Write-Host "`nComputer '$searchComputer' does not exist in DC." -ForegroundColor White
            Write-Log "`nComputer '$searchComputer' does not exist in DC."
        }
    } else {
        Write-Host "Invalid selection, please choose 1 for Users or 2 for Computers." -ForegroundColor White
        Write-Log "Invalid selection, please choose 1 for Users or 2 for Computers."
        continue
    }
}




# Get system information for logging at the end of the script
$hostname = hostname
$user = whoami
$osVersion = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
$domainjoined? = (Get-WmiObject -Class Win32_ComputerSystem).Domain

# Log the system information

# Display information in green
Write-Host "Hostname: $hostname" -ForegroundColor Green
Write-Host "User: $user" -ForegroundColor Green
Write-Host "Operating System: $osVersion" -ForegroundColor Green
Write-Host "Computer is Domain joined? $domainjoined" -ForegroundColor Green

# Stop network trace after LDAP authentication and query
Write-OutputAndLog "Stopping network trace..." -ForegroundColor Yellow

netsh trace stop
