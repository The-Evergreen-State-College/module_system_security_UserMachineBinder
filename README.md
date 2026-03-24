<div align="center">
<img src="/assets/images/User-machine-Binding-logo.jpg" alt="UMB Logo" width="200" height="300"/>
</div>

# module_system_security_UserMachineBinder

## :world_map: About
UMB (User Machine Binder) is an enterprise-minded Windows security module that binds a specific user to a computer adding a layer of security for restricted environments. Though primarily intended for Windows Domain Networks, works just as well for standalone computers using local windows accounts.

## :japanese_castle: Security Description
Windows OS uses the security policy configured in Group Policy {local, domain}: `Computer Policy/Windows Settings/Security Settings/Local Policies/User Rights Assignment/Allow log on locally` that controls which users can log on locally via console. Though Group Policy is a GUI interface for setting registry keys, in the case of `Allow log on locally`, it is handled by [Local Security Authority (LSA)](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection) which makes it difficult to configure without a tool that can modify any settings going through the LSAS (Local Security Authority Service). LSA settings are kept in the registry (`HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets`) which reads a binary database (`C:\Windows\System32\config\SECURITY`). [Automated methods](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/windows-registry-advanced-users) for changing registry keys in this case do not work, since the key (HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets) is read from `C:\Windows\System32\config\SECURITY`

## :robot: Solution Description: To Automate
To manually configure user binding is easy enough using {local, domain} Group Policy and setting `Computer Policy/Windows Settings/Security Settings/Local Policies/User Rights Assignment/Allow log on locally`.

How to dynamically and automate configuration for this setting that enables user machine binding? 

module_system_security_UserMachineBinder (UMB) provides an automated mechanism to dynamically assign a user/group using a key-value-pair file database.
Next, UMB uses the Powershell module [Carbon](https://get-carbon.org/) to Configure LSA with user right `Allow log on locally`.  


### :gear: How it works

#### Step-by-step flow:

    1. Bootstraps dependencies — Installs NuGet, sets PSGallery as trusted, and installs the Carbon PowerShell module if not already present.
    2. Gets the computer name — Uses $env:COMPUTERNAME to identify the current machine.
    3. Looks up the assigned user — Reads config\UMB-Mapping.txt, a key-value-pair file (COMPUTERNAME=USERNAME), and finds the entry for the current machine. Exits with an error if the computer isn't listed.
    4. Grants logon rights — Calls Grant-CPrivilege -Identity $UserName -Privilege SeInteractiveLogonRight to give the bound user the Allow log on locally right.
    5. Revokes rights for others — Reads config\revoke-UMB.txt (a list of users/groups) and calls Revoke-CPrivilege for each, stripping their logon rights.
    6. Done — Prints a completion message and exits cleanly.


## :thinking: Considerations
- By default, Domain Group Policy will add `domain users` to the local `Users` group, which in turn by default is configured with `Allow logon locally` privilege, giving all domain users the privilege of console log on.
  - Mitigation: revoke `Users` from `Allow logon locally` privilege.
- Default Powershell execution policy is restrictive and needs to be configured to allow running scripts
  - `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force`
- [Microsoft recommendations for added LSA protection.](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)

### :notebook: [Change Log](ChangeLog.md)

#### :dart: Roadmap
- [ ] Logging to file.
- [ ] Improved output.
- [ ] Create a standalone package for off-line use. 
