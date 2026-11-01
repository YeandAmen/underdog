[CmdletBinding()]
param([switch]$SeedMisconfigurations)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$domain = Get-ADDomain
$root = "OU=IdentityShield,$($domain.DistinguishedName)"
foreach ($definition in @(
    @{Name='IdentityShield';Path=$domain.DistinguishedName},
    @{Name='Staff';Path=$root},
    @{Name='Groups';Path=$root}
)) {
    $dn = "OU=$($definition.Name),$($definition.Path)"
    if (-not (Get-ADOrganizationalUnit -Filter 'DistinguishedName -eq $dn')) {
        New-ADOrganizationalUnit -Name $definition.Name -Path $definition.Path
    }
}
$groupPath = "OU=Groups,$root"
$globalGroups = @('GG_Helpdesk','GG_Finance','GG_HR','GG_OT_Engineers','GG_IT_Administrators','GG_Backup')
$localGroups = @('DL_Staff_ResetPassword','DL_Engineering_LocalAdmin','DL_Directory_Replication','DL_Finance_ReadWrite')
foreach ($name in ($globalGroups + $localGroups)) {
    $existing = Get-ADGroup -Filter 'SamAccountName -eq $name'
    if ($existing -and -not $existing.DistinguishedName.EndsWith($groupPath,[StringComparison]::OrdinalIgnoreCase)) {
        throw "Existing group $name is outside the lab OU. Choose a different lab namespace."
    }
    if (-not $existing) {
        $scope = if ($name.StartsWith('GG_')) {'Global'} else {'DomainLocal'}
        New-ADGroup -Name $name -SamAccountName $name -GroupScope $scope -GroupCategory Security -Path $groupPath
    }
}
$password = Read-Host 'Initial password for the six dedicated lab accounts' -AsSecureString
$roster = @{
    'maya.chen'='GG_Helpdesk';'noah.williams'='GG_Finance';'ava.patel'='GG_HR';
    'leo.martin'='GG_OT_Engineers';'alex.rivera'='GG_IT_Administrators';'svc.backup'='GG_Backup'
}
$staffPath = "OU=Staff,$root"
foreach ($name in $roster.Keys) {
    $existing = Get-ADUser -Filter 'SamAccountName -eq $name'
    if ($existing -and -not $existing.DistinguishedName.EndsWith($staffPath,[StringComparison]::OrdinalIgnoreCase)) {
        throw "Existing account $name is outside the lab OU. It was not modified."
    }
    if (-not $existing) {
        New-ADUser -Name $name -SamAccountName $name -UserPrincipalName "$name@$($domain.DNSRoot)" -Path $staffPath -AccountPassword $password -Enabled $true
    }
    $member = Get-ADUser $name
    if (-not (Get-ADGroupMember $roster[$name] | Where-Object DistinguishedName -eq $member.DistinguishedName)) {
        Add-ADGroupMember -Identity $roster[$name] -Members $member
    }
}
$edges = @{
    'DL_Staff_ResetPassword'=@('GG_Helpdesk');
    'DL_Engineering_LocalAdmin'=@('GG_OT_Engineers');
    'DL_Directory_Replication'=@('GG_IT_Administrators');
    'DL_Finance_ReadWrite'=@('GG_Finance')
}
if ($SeedMisconfigurations) {
    $edges['DL_Engineering_LocalAdmin'] += 'GG_Helpdesk'
    $edges['DL_Directory_Replication'] += 'GG_Backup'
    $edges['DL_Finance_ReadWrite'] += 'GG_Helpdesk'
}
foreach ($parent in $edges.Keys) {
    foreach ($child in $edges[$parent]) {
        $group = Get-ADGroup $child
        if (-not (Get-ADGroupMember $parent | Where-Object DistinguishedName -eq $group.DistinguishedName)) {
            Add-ADGroupMember -Identity $parent -Members $group
        }
    }
}
$resetGroup = Get-ADGroup 'DL_Staff_ResetPassword'
$aclPath = "AD:\$staffPath"
$acl = Get-Acl $aclPath
$resetGuid = [guid]'00299570-246d-11d0-a768-00aa006e0529'
$userClass = [guid]'bf967aba-0de6-11d0-a285-00aa003049e2'
$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $resetGroup.SID,
    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
    [System.Security.AccessControl.AccessControlType]::Allow,
    $resetGuid,
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
    $userClass
)
if (-not ($acl.Access | Where-Object {$_.ObjectType -eq $resetGuid -and $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $resetGroup.SID.Value})) {
    $acl.AddAccessRule($rule)
    Set-Acl -Path $aclPath -AclObject $acl
}
if ($SeedMisconfigurations) {
    $replicationGroup = Get-ADGroup 'DL_Directory_Replication'
    $domainPath = "AD:\$($domain.DistinguishedName)"
    $domainAcl = Get-Acl $domainPath
    foreach ($guid in @('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')) {
        $right = [guid]$guid
        if (-not ($domainAcl.Access | Where-Object {$_.ObjectType -eq $right -and $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $replicationGroup.SID.Value})) {
            $replicationRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($replicationGroup.SID,[System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,[System.Security.AccessControl.AccessControlType]::Allow,$right)
            $domainAcl.AddAccessRule($replicationRule)
        }
    }
    Set-Acl -Path $domainPath -AclObject $domainAcl
}
Write-Output "Lab OU ready: $root"
Write-Output 'Engineering local-admin membership and actual file-share permissions must be configured on their dedicated lab endpoints.'
