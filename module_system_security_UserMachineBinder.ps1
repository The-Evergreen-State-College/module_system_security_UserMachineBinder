<#
.SYNOPSIS
    Binds a specific user/group to a computer by configuring logon privileges using a key-value mapping file.

.DESCRIPTION
    This script automates user-machine binding for security in restricted environments. It reads a configuration file to map computers to users/groups, grants 'Allow log on locally' rights to the specified user, and revokes rights for others listed in a revoke file. Requires administrator privileges and the Carbon module.

.PARAMETER ConfigFile
    Path to the UMB-Mapping.txt file. Defaults to script-relative 'config\UMB-Mapping.txt'.

.EXAMPLE
    .\module_system_security_UserMachineBinder.ps1
    Binds the user for the current computer based on UMB-Mapping.txt and revokes rights for users/groups in revoke-UMB.txt.

.Notes
    Author:		David Geeraerts
    Location:	Olympia, Washington USA
    E-Mail:		dgeeraerts.evergreen@gmail.com
    GitHub:     https://github.com/DavidGeeraerts
    Project:    https://github.com/The-Evergreen-State-College/module_system_security_UserMachineBinder
    License:    GNU GPL v3.0 (https://www.gnu.org/licenses/gpl-3.0.en.html) 
    Version:    1.3.0   (Semantic Versioning: http://semver.org/)

.LINK
    https://github.com/The-Evergreen-State-College/module_system_security_UserMachineBinder
    https://www.gnu.org/licenses/gpl-3.0.en.html
    https://get-carbon.org/
    http://semver.org/
#>

###############################################################################
# Requires -RunAsAdministrator
###############################################################################

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigFile = (Join-Path -Path $PSScriptRoot -ChildPath 'config\UMB-Mapping.txt')
)

# Global variables for script metadata
$SCRIPT_NAME = 'module_system_security_UserMachineBinder'
$SCRIPT_VERSION = '1.3.0'
$SCRIPT_BUILD = '20260407'

# User supplied configuration file path, if provided as a parameter
# Resolve the config file path: if user provided a full path, use it; otherwise, assume it's a filename in config\
if ($ConfigFile -match '[/\\]') {
    # Looks like a full path (contains / or \), use as-is
    $UserMachineBinderConfigFilePath = $ConfigFile
} else {
    # Assume it's just a filename, prepend the script-relative config path
    $UserMachineBinderConfigFilePath = Join-Path -Path $PSScriptRoot -ChildPath "config\$ConfigFile"
}

# Ensure the config directory exists
$configDir = Split-Path -Path $UserMachineBinderConfigFilePath -Parent
if (!(Test-Path -Path $configDir)) {
    throw "Config directory '$configDir' does not exist. Ensure the config folder is present."
    Start-Sleep -Seconds 10  # pause for user to read
    exit 1
}


# function for banner creation
function Show-Banner {
    param(
        [string]$Step = "Start",
        [string]$Message = "starting script execution..."
    )
    Clear-Host
    Write-Host "-----------------------------------------------" -ForegroundColor White
    Write-Host "Name: $SCRIPT_NAME" -ForegroundColor Blue
    Write-Host "Version: $SCRIPT_VERSION" -ForegroundColor White
    Write-Host ""
    Write-Host "Computer: $env:COMPUTERNAME"
    Write-Host "UMB Config File: $UserMachineBinderConfigFilePath"
    Write-Host "Step: $Step" -ForegroundColor Cyan
    Write-Host "-----------------------------------------------" -ForegroundColor White
    write-Host ""
    Write-Host "Message: $Message" -ForegroundColor Green
}


# Start of script
Show-Banner -Step "Initialization" -Message "Checking for administrator privileges and required dependencies."

# Check if running as administrator
Write-Host "Checking for administrator privileges..." -ForegroundColor DarkGray
if (-not ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    Write-Error "This script must be run as an administrator. Please right-click and 'Run as administrator'."
    Start-Sleep -Seconds 10  # pause for user to read
    exit 1
}

# Allow running Carbon module scripts
Write-Host "Ensuring execution policy for current user allows running Carbon module scripts..." -ForegroundColor DarkGray
if ((Get-ExecutionPolicy) -ne 'RemoteSigned') { Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force }

Show-Banner -Step "Dependency Check" -Message "Checking for required dependencies and importing modules."

# Check for PowerShell version 4.0 or higher, which is required for Carbon module.
if ($PSVersionTable.PSVersion.Major -lt 4) { throw "Requires PowerShell 4.0 or higher." }


$carbonManifest = Join-Path $PSScriptRoot 'lib\Carbon\Carbon.psd1'
if (Test-Path $carbonManifest) {
    Write-Host "Loading Carbon from local source: $carbonManifest" -ForegroundColor DarkGray
    Import-Module $carbonManifest -Force -ErrorAction Stop
}
else {
    Write-Host "Local Carbon not found, installing from PSGallery..." -ForegroundColor Yellow
    # NuGet package is required for PSGallery
    # Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.
    if (!(Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) { Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.208 -Force }
    # PSGallery is required for Carbon module installation
    if (!(Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)) { Set-PSRepository -name PSGallery -InstallationPolicy Trusted }
    # Carbon module is required for UserMachineBinder module
    if (!(Get-Module -Name Carbon -ListAvailable)) { Install-Module -Name Carbon -Force }
    # Check to see if Carbon is imported, if not import it
    ## Carbon is necessary for this script to function, so if it cannot be imported, the script will exit with an error message.
    try {
        Import-Module -Name Carbon -Force
    } catch {
        Write-Error "Failed to import the Carbon module. Ensure it is installed and accessible!"
        Start-Sleep -Seconds 30
        exit 1
    }
}



# Get the computer name
$ComputerName = $env:COMPUTERNAME

Show-Banner -Step "Mapping Validation" -Message "Checking if computer:$ComputerName exists in configuration file..."

# If the computer name is not found in the configuration file, throw an error and exit
if (!(Select-String -Path $UserMachineBinderConfigFilePath -Pattern "$ComputerName" -SimpleMatch -Quiet)) {
    Write-Host "Computer name '$ComputerName' not found in UserMachineBinder configuration file at '$UserMachineBinderConfigFilePath'." -ForegroundColor Red
    Write-Host "Add an entry for this computer and try again." -ForegroundColor Red
    Start-Sleep -Seconds 30
    exit 1
}

# Checking for duplicate entries
# Remove comments and extract keys from the configuration file for validation
$activeKeys = Get-Content -Path $UserMachineBinderConfigFilePath | 
    Where-Object { $_ -notmatch '^\s*#' -and $_ -match '\S' } |
    ForEach-Object {
        # 2. Extract just the Key (the part before the =)
        # split by '=' and take the first part [0]
        $_.Split('=')[0].Trim()
}

# Check the mapping file for duplicate computer names and throw a warning if duplicates are found
$DuplicateComputers = $activeKeys | 
    Group-Object |
    Where-Object { $_.Count -gt 1 } |
    Select-Object -ExpandProperty Name

# If duplicates are found, display a warning message with the duplicate computer names
if ($DuplicateComputers) {
    Write-Warning "The following computer names appear more than once in the configuration file: $DuplicateComputers"
}

# If the current computer name is found in the list of duplicates, throw an error and exit to prevent unintended consequences of multiple entries for the same computer
if ($DuplicateComputers -contains $ComputerName) {
    Write-Host "The current machine '$env:COMPUTERNAME' is defined multiple times in the configuration file!" -ForegroundColor Red
    Write-Host "Remove duplicate entries for this computer and try again." -ForegroundColor Red
    Start-Sleep -Seconds 30
    exit 1
}

Show-Banner -Step "Get-Mapping" -Message "Retrieving user/group mapping for computer: $ComputerName from configuration file."
# set the user name variable to the user name found in the configuration file for this computer
$UserName = (Select-String -Path $UserMachineBinderConfigFilePath -Pattern $ComputerName -SimpleMatch).Line.Split('=')[1].Trim()
# check if the user name variable is null or empty and throw an error if it is
if ([string]::IsNullOrWhiteSpace($UserName)) {
    Write-Host "User name for computer '$ComputerName' is null or empty in the configuration file!" -ForegroundColor Red
    Write-Host "Ensure there is a valid user name for this computer in the configuration file and try again." -ForegroundColor Yellow
    Start-Sleep -Seconds 30
    exit 1
}

Show-Banner -Step "Granting Logon Rights" -Message "Granting Logon Rights to User/Group for Computer: $ComputerName"
# Bind the user/group account to the computer account using Carbon's privilege function
# -Privilege values are case sensitive and must be exactly as defined in the Carbon module's documentation
Grant-CPrivilege -Identity $UserName -Privilege SeInteractiveLogonRight
# Confirmation message
if (Test-CPrivilege -Identity $UserName -Privilege SeInteractiveLogonRight) {
    Write-Host "User $UserName has been successfully bound to computer $ComputerName. Logon rights have been configured."
    } else {
    Write-Host "Verification failed: Logon rights were not granted to user '$UserName' on computer '$ComputerName'." -ForegroundColor Red
    Start-Sleep -Seconds 30
    exit 1 
}

Show-Banner -Step "Revoking Logon Rights" -Message "Revoking Logon Rights for User/Group Accounts"
# Revoke the user/group account's log on locally right to prevent local logins
# Run for loop to revoke the log on locally right for the user/group account
$RevokeFilePath = Join-Path -Path  $PSScriptRoot -ChildPath 'config\revoke-UMB.txt'
Write-Host "Revoking the following user/group accounts from log on locally rights as listed in '$RevokeFilePath':" -ForegroundColor Yellow
Get-Content $RevokeFilePath
$RevokeList = Get-Content -Path $RevokeFilePath
foreach ($Identity in $RevokeList) {
    $Identity = $Identity.Trim()
    if ($Identity) {
        write-Host "Processing User/Group $Identity..." -ForegroundColor DarkMagenta
        Revoke-CPrivilege -Identity $Identity -Privilege SeInteractiveLogonRight
    }
}

# Confirmation loop to verify that the log on locally right has been revoked for each user/group account in the revoke list
foreach ($Identity in $RevokeList) {
    $Identity = $Identity.Trim()
    if (-not $Identity) { continue }

    if (Test-CPrivilege -Identity $Identity -Privilege SeInteractiveLogonRight) {
        Write-Host "FAILED: '$Identity' still has SeInteractiveLogonRight." -ForegroundColor Red
        Start-Sleep -Seconds 30
        exit 1
    } else {
        Write-Host "Confirmed: '$Identity' does not have SeInteractiveLogonRight." -ForegroundColor Cyan
    }
}
Start-Sleep 10

# End
Show-Banner -Step "Finished" -Message "Completed User-Machine Binding for Computer: $ComputerName to User: $UserName"
Start-Sleep -Seconds 5
exit 0