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
    Version:    1.1.0   (Semantic Versioning: http://semver.org/)

.LINK
    https://github.com/The-Evergreen-State-College/module_system_security_UserMachineBinder
    https://www.gnu.org/licenses/gpl-3.0.en.html
    https://get-carbon.org/
    http://semver.org/
#>


###############################################################################
# Requires -RunAsAdministrator
###############################################################################

# Global variables for script metadata
$SCRIPT_NAME = 'module_system_security_UserMachineBinder'
$SCRIPT_VERSION = '1.1.0'
$SCRIPT_BUILD = '20260331'

# Start of script
Write-Host "Starting $SCRIPT_NAME version $SCRIPT_VERSION..."
Write-Host ""

# Check if running as administrator
Write-Host "Checking for administrator privileges..." -ForegroundColor DarkGray
if (-not ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    Write-Error "This script must be run as an administrator. Please right-click and 'Run as administrator'."
    Start-Sleep -Seconds 10  # pause for user to read
    exit 1
}

Write-Host "Checking dependencies..." -ForegroundColor DarkGray
# NuGet package is required for PSGallery
# Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.
if (!(Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) { Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.208 -Force }

# PSGallery is required for Carbon module installation
if (!(Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)) { Set-PSRepository -name PSGallery -InstallationPolicy Trusted }

# Carbon module is required for UserMachineBinder module
if (!(Get-Module -Name Carbon -ListAvailable)) { Install-Module -Name Carbon -Force }

# Allow running Carbon module scripts
if ((Get-ExecutionPolicy) -ne 'RemoteSigned') { Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force }

# Check to see if Carbon is imported, if not import it
## Carbon is necessary for this script to function, so if it cannot be imported, the script will exit with an error message.
try {
    Import-Module -Name Carbon -Force
} catch {
    Write-Error "Failed to import the Carbon module. Ensure it is installed and accessible!"
    Start-Sleep -Seconds 30
    exit 1
}

# Get the computer name
$ComputerName = $env:COMPUTERNAME

# Search for the computer name  in the UserMachineBinder module's configuration file
$UserMachineBinderConfigFilePath = Join-Path -Path  $PSScriptRoot -ChildPath 'config\UMB-Mapping.txt'
# If the computer name is not found in the configuration file, throw an error and exit
if (!(Select-String -Path $UserMachineBinderConfigFilePath -Pattern "$ComputerName" -SimpleMatch -Quiet)) {
    Write-Error "Computer name '$ComputerName' not found in UserMachineBinder configuration file at '$UserMachineBinderConfigFilePath'. Please add an entry for this computer and try again."
    Start-Sleep -Seconds 30
    exit 1
}

# set the user name variable to the user name found in the configuration file for this computer
$UserName = (Select-String -Path $UserMachineBinderConfigFilePath -Pattern $ComputerName).Line.Split('=')[1].Trim()

# Bind the user/group account to the computer account using Carbon's privilege function
# -Privilege values are case sensitive and must be exactly as defined in the Carbon module's documentation
Grant-CPrivilege -Identity $UserName -Privilege SeInteractiveLogonRight
# Confirmation message
if (Test-CPrivilege -Identity $UserName -Privilege SeInteractiveLogonRight) {
    Write-Host "User $UserName has been successfully bound to computer $ComputerName. Logon rights have been configured."
    } else {
    Write-Error "Verification failed: Logon rights were not granted to user '$UserName' on computer '$ComputerName'."
    Start-Sleep -Seconds 30
    exit 1  # Optional: Exit on failure
}

# Revoke the user/group account's log on locally right to prevent local logins
# Run for loop to revoke the log on locally right for the user/group account
$RevokeFilePath = Join-Path -Path  $PSScriptRoot -ChildPath 'config\revoke-UMB.txt'
Write-Host "Revoking the following user/group accounts from log on locally rights as listed in '$RevokeFilePath':" -ForegroundColor Yellow
Get-Content $RevokeFilePath
$RevokeList = Get-Content -Path $RevokeFilePath
foreach ($Identity in $RevokeList) {
    $Identity = $Identity.Trim()
    if ($Identity) {
        Revoke-CPrivilege -Identity $Identity -Privilege SeInteractiveLogonRight
    }
    write-Host "User/Group $Identity has been revoked the log on locally right to prevent local logins." -ForegroundColor cyan
}

# End
Write-Host "Finished!" -ForegroundColor green
Start-Sleep -Seconds 5
exit 0