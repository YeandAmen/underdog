[CmdletBinding()]
param([Parameter(Mandatory)][string]$WindowsBaseVhd,[Parameter(Mandatory)][string]$RangePath,[switch]$Start)
$ErrorActionPreference='Stop'
Import-Module Hyper-V
$base=(Resolve-Path $WindowsBaseVhd).Path
if(-not $base.EndsWith('.vhdx',[StringComparison]::OrdinalIgnoreCase)){throw 'Supply a generalized Windows Server VHDX.'}
$switch='IdentityShield-Isolated'
if(-not (Get-VMSwitch -Name $switch -ErrorAction SilentlyContinue)){New-VMSwitch -Name $switch -SwitchType Private | Out-Null}
New-Item -ItemType Directory -Path $RangePath -Force | Out-Null
foreach($node in @(@{Name='DC01';Memory=4GB},@{Name='WS01';Memory=4GB},@{Name='ENG01';Memory=4GB})) {
    $name="IdentityShield-$($node.Name)"
    $disk=Join-Path $RangePath "$name.vhdx"
    $existing=Get-VM -Name $name -ErrorAction SilentlyContinue
    if($existing){Write-Output "Preserved existing VM: $name";continue}
    if(Test-Path $disk){throw "Disk $disk already exists without the expected VM; inspect it before provisioning."}
    New-VHD -Path $disk -ParentPath $base -Differencing | Out-Null
    New-VM -Name $name -Generation 2 -MemoryStartupBytes $node.Memory -VHDPath $disk -SwitchName $switch | Out-Null
    Set-VMProcessor -VMName $name -Count 2
    if($Start){Start-VM -Name $name}
    Write-Output "Provisioned $name on $switch"
}
