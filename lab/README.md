# Reproducible lab

The Go workspace runs on macOS/Linux/Windows. AD setup and collection execute on
Windows with the ActiveDirectory module; Hyper-V provisioning executes on a
Windows Hyper-V host. These scripts are not executed by opening the web app.

## Directory setup

1. Prepare a Windows Server domain controller in a dedicated lab domain.
2. On the controller, run the scoped setup. It creates its own `IdentityShield`
   OU, role groups, six lab accounts, and a helpdesk password-reset delegation.

```powershell
./Initialize-Lab.ps1 -SeedMisconfigurations
```

The switch additionally nests Helpdesk into the engineering-admin and Finance
permission groups and adds Backup to the directory-replication permission group.
It does not add those groups to production resources.

3. Join a lab engineering workstation to the domain and add the lab engineering
   permission group to its local Administrators group, using that VM's domain:

```powershell
Add-LocalGroupMember -Group (Get-LocalGroup -SID 'S-1-5-32-544').Name -Member 'YOURDOMAIN\DL_Engineering_LocalAdmin'
```

4. Edit `policy.example.json` to use the actual host names, addresses, domain
   root DN, and lab Staff OU DN. Roles and allowed actions are explicit business
   policy; they are not inferred from whatever privileges currently exist.

## Collect identity and event evidence

```powershell
./windows/Export-Identity.ps1 -PolicyFile ./policy.example.json -OutputFile ./snapshot.json
./windows/Export-Events.ps1 -OutputFile ./events.jsonl -MaxEvents 20000

# Or export a downloaded/native EVTX sample:
./windows/Export-Events.ps1 -Path ./sample.evtx -OutputFile ./sample.jsonl
```

Import the snapshot in **Identity**, then the events in **Datasets** using the
Windows JSONL adapter and source **windows**. The identity snapshot binds policy
context to this source. Other public captures remain separate even if account
names coincide.

The identity collector is scope-limited. It reads the configured OU, resolves
known principal memberships, reads selected OU/domain delegation rights, and
queries local Administrators on configured workstation/server assets using
WinRM. It exports only supported normalized actions. Cross-scope principals and
arbitrary GPO/AccessCheck semantics are not represented as verified full access.
The collector fails on an inaccessible configured resource rather than silently
claiming a complete successful collection.

For full directory-change evidence, configure the Windows audit policy and
appropriate object SACLs for the chosen scenarios. Sysmon alone does not provide
all AD object-permission changes.

## Hyper-V range

`hyperv/New-Range.ps1` provisions isolated differencing-disk VMs from an existing,
generalized Windows Server VHDX. Images, licences, passwords, and VM disks are
not supplied by the repository. Existing VM names are preserved.

```powershell
./hyperv/New-Range.ps1 -WindowsBaseVhd 'D:\Images\server-generalized.vhdx' -RangePath 'D:\IdentityShield' -Start
```

Configure the domain and guest hostnames inside the VMs, then use the scoped
setup and collectors. The Go app can remain on the host; offline exports can be
imported without exposing its HTTP service to the VM network.
