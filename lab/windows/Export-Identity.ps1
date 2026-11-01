[CmdletBinding()]
param([Parameter(Mandatory)][string]$PolicyFile,[string]$OutputFile='./snapshot.json')
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$policy = Get-Content -Raw $PolicyFile | ConvertFrom-Json
$adUsers = @(Get-ADUser -SearchBase $policy.search_base -Filter * -Properties MemberOf,Department,Enabled)
$adGroups = @(Get-ADGroup -SearchBase $policy.search_base -Filter * -Properties Member)
$principals = @{}
foreach ($principal in ($adUsers + $adGroups)) {$principals[$principal.SID.Value]=$principal.SamAccountName.ToLowerInvariant()}
$groups = @($adGroups | ForEach-Object {
    $group=$_
    $members=@(foreach ($dn in $group.Member) {
        $object=Get-ADObject -Identity $dn -Properties objectSid
        if ($object.objectSid -and $principals.ContainsKey($object.objectSid.Value)) {$principals[$object.objectSid.Value]}
    })
    @{id=$group.SamAccountName.ToLowerInvariant();name=$group.Name;members=$members}
})
$users = @($adUsers | ForEach-Object {
    $user=$_;$declared=$policy.users | Where-Object name -eq $user.SamAccountName | Select-Object -First 1
    $memberOf=@(foreach ($dn in $user.MemberOf) {
        $group=Get-ADGroup $dn
        if ($principals.ContainsKey($group.SID.Value)) {$principals[$group.SID.Value]}
    })
    @{id=$user.SamAccountName.ToLowerInvariant();sid=$user.SID.Value;name=$user.SamAccountName;role=$(if($declared){$declared.role}else{'Unassigned'});department=$(if($declared){$declared.department}else{$user.Department});groups=$memberOf;enabled=[bool]$user.Enabled}
})
$grants = New-Object System.Collections.Generic.List[object]
$grantIDs = @{}
$assets = @($policy.assets | ForEach-Object {@{id=$_.id;name=$_.name;kind=$_.kind;zone=$_.zone;critical=[bool]$_.critical;address=$_.address}})
function Add-Grant($principal,$resource,$right,$effect,$inherited,$depth,$origin) {
    $id="$resource-$principal-$right-$effect-$depth"
    if(-not $grantIDs.ContainsKey($id)) {
        $grantIDs[$id]=$true
        $grants.Add(@{id=$id;principal=$principal;resource=$resource;right=$right;effect=$effect;inherited=[bool]$inherited;inherited_depth=[int]$depth;origin=$origin})
    }
}
function Ace-Depth($dn,$ace) {
    if(-not $ace.IsInherited){return 0}
    $depth=0;$parent=$dn
    while($parent.Contains(',')) {
        $parent=$parent.Substring($parent.IndexOf(',')+1);$depth++
        if(-not $parent.StartsWith('OU=') -and -not $parent.StartsWith('DC=')){continue}
        $parentAcl=Get-Acl "AD:\$parent"
        foreach($candidate in $parentAcl.Access) {
            if(-not $candidate.IsInherited -and $candidate.IdentityReference.Value -eq $ace.IdentityReference.Value -and $candidate.ObjectType -eq $ace.ObjectType -and $candidate.AccessControlType -eq $ace.AccessControlType -and $candidate.ActiveDirectoryRights -eq $ace.ActiveDirectoryRights){return $depth}
        }
        if($parent -eq (Get-ADDomain).DistinguishedName){break}
    }
    throw "Cannot resolve the inheritance origin for a configured grant on $dn."
}
foreach($asset in $policy.assets) {
    if($asset.scope_dn) {
        $acl=Get-Acl "AD:\$($asset.scope_dn)"
        $replication=@{}
        foreach($ace in $acl.Access) {
            $sid=$ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
            if(-not $principals.ContainsKey($sid)){continue}
            if(-not ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight)){continue}
            $principal=$principals[$sid];$effect=$ace.AccessControlType.ToString().ToLowerInvariant();$depth=Ace-Depth $asset.scope_dn $ace
            if($asset.kind -eq 'organizational-unit' -and $ace.InheritanceType.ToString() -ne 'None' -and $ace.ObjectType -eq [guid]'00299570-246d-11d0-a768-00aa006e0529' -and ($ace.InheritedObjectType -eq [guid]::Empty -or $ace.InheritedObjectType -eq [guid]'bf967aba-0de6-11d0-a285-00aa003049e2')) {
                Add-Grant $principal $asset.id 'reset-password' $effect $ace.IsInherited $depth $asset.scope_dn
            }
            if($asset.kind -eq 'domain-controller') {
                $bit=0
                if($ace.ObjectType -eq [guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'){$bit=1}
                if($ace.ObjectType -eq [guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'){$bit=2}
                if($ace.ObjectType -eq [guid]::Empty){$bit=3}
                if($bit){$key="$principal|$effect|$depth";if(-not $replication.ContainsKey($key)){$replication[$key]=@{mask=0;principal=$principal;effect=$effect;depth=$depth;inherited=$ace.IsInherited}};$replication[$key].mask=$replication[$key].mask -bor $bit}
            }
        }
        foreach($entry in $replication.Values){if($entry.mask -eq 3){Add-Grant $entry.principal $asset.id 'replicate-directory' $entry.effect $entry.inherited $entry.depth $asset.scope_dn}}
    }
    if($asset.kind -in @('workstation','engineering-workstation','file-server')) {
        $members=Invoke-Command -ComputerName $asset.name -ScriptBlock {Get-LocalGroupMember -Group (Get-LocalGroup -SID 'S-1-5-32-544').Name | Select-Object -ExpandProperty SID | ForEach-Object {$_.Value}}
        foreach($sid in $members){if($principals.ContainsKey($sid)){Add-Grant $principals[$sid] $asset.id 'local-admin' 'allow' $false 0 'Observed endpoint local Administrators membership'}}
    }
}
$snapshot=[ordered]@{
    id="windows-$([guid]::NewGuid().ToString('N'))";organization=$policy.organization;policy_version=$policy.policy_version;
    captured_at=[datetime]::UtcNow.ToString('o');source='windows';event_sources=@('windows');users=$users;groups=$groups;assets=$assets;
    grants=@($grants.ToArray());policies=@($policy.policies);approvals=@($policy.approvals)
}
$json=$snapshot | ConvertTo-Json -Depth 15
[IO.File]::WriteAllText([IO.Path]::GetFullPath($OutputFile),$json,(New-Object System.Text.UTF8Encoding($false)))
Write-Output "Scoped identity snapshot exported to $OutputFile. External principals and unsupported actions are not represented as complete effective permissions."
