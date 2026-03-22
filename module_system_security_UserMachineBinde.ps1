<#
.SYNOPSIS
    Binds a specific user/group to a computer by configuring logon privileges using a key-value mapping file.

.DESCRIPTION
    This script automates user-machine binding for security in restricted environments. It reads a configuration file to map computers to users/groups, grants 'Allow log on locally' rights to the specified user, and revokes rights for others listed in a revoke file. Requires administrator privileges and the Carbon module.

.PARAMETER ConfigFile
    Path to the UMB-Mapping.txt file. Defaults to script-relative 'config\UMB-Mapping.txt'.

.EXAMPLE
    .\module_system_security_UserMachineBinde.ps1
    Binds the user for the current computer based on UMB-Mapping.txt and revokes rights for users/groups in revoke-UMB.txt.

.Notes
    Author:		David Geeraerts
    Location:	Olympia, Washington USA
    E-Mail:		dgeeraerts.evergreen@gmail.com
    GitHub:     https://github.com/DavidGeeraerts
    Project:    https://github.com/The-Evergreen-State-College/module_system_security_UserMachineBinder
    License:    GNU GPL v3.0 (https://www.gnu.org/licenses/gpl-3.0.en.html) 
    Version:    1.0.0   (Semantic Versioning: http://semver.org/)

.LINK
    https://github.com/The-Evergreen-State-College/module_system_security_UserMachineBinder
    https://www.gnu.org/licenses/gpl-3.0.en.html
    https://get-carbon.org/
    http://semver.org/
#>


###############################################################################
# Requires -RunAsAdministrator
###############################################################################

# NuGet package is required for PSGallery
# Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.
if (!(Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) { Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.208 -Force }

# PSGallery is required for Carbon module installation
if (!(Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)) { set-PSRepository -name PSGallery -InstallationPolicy Trusted}

# Carbon module is required for UserMachineBinder module
if (!(Get-Module -Name Carbon -ListAvailable)) { Install-Module -Name Carbon -Force }

# Allow running Carbon module scripts
if ((Get-ExecutionPolicy) -ne 'RemoteSigned') { Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force }

# Check to see if Carbon is imported, if not import it
if (!(Get-Module -Name Carbon -ListAvailable)) { Import-Module -Name Carbon -Force }

# Get the computer name
$ComputerName = $env:COMPUTERNAME

# Search for the computer name  in the UserMachineBinder module's configuration file
$UserMachineBinderConfigFilePath = Join-Path -Path  $PSScriptRoot -ChildPath 'config\UMB-Mapping.txt'
# If the computer name is not found in the configuration file, throw an error and exit
if (!(Select-String -Path $UserMachineBinderConfigFilePath -Pattern $ComputerName -Quiet)) {
    Write-Error "Computer name '$ComputerName' not found in UserMachineBinder configuration file at '$UserMachineBinderConfigFilePath'. Please add an entry for this computer and try again."
    exit 1
}
# set the user name variable to the user name found in the configuration file for this computer
$UserName = (Select-String -Path $UserMachineBinderConfigFilePath -Pattern $ComputerName).Line.Split('=')[1].Trim()


# Bind the user/group account to the computer account using Carbon's privilege function
# -Privilege values are case sensitive and must be exactly as defined in the Carbon module's documentation
Grant-CPrivilege -Identity $UserName -Privilege SeInteractiveLogonRight
Write-Host "User $UserName has been successfully bound to computer $ComputerName. Logon rights have been configured."


# Revoke the user/group account's log on locally right to prevent local logins
# Run for loop to revoke the log on locally right for the user/group account

$RevokeFilePath = Join-Path -Path  $PSScriptRoot -ChildPath 'config\revoke-UMB.txt'
$RevokeList = Get-Content -Path $RevokeFilePath
foreach ($Identity in $RevokeList) {
    $Identity = $Identity.Trim()
    if ($Identity) {
        Revoke-CPrivilege -Identity $Identity -Privilege SeInteractiveLogonRight
    }
write-Host "User $Identity has been revoked the log on locally right to prevent local logins."
}

# End
Write-Host "Finished!"
Start-Sleep -Seconds 5
exit 0