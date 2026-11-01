[CmdletBinding()]
param(
    [string]$Path,
    [string[]]$LogName = @('Security','Microsoft-Windows-Sysmon/Operational'),
    [string]$OutputFile = './events.jsonl',
    [int]$MaxEvents = 20000,
    [datetime]$Since = (Get-Date).AddDays(-1)
)
$ErrorActionPreference = 'Stop'
if ($MaxEvents -lt 1 -or $MaxEvents -gt 200000) {throw 'MaxEvents must be 1..200000.'}
$events = if ($Path) {
    Get-WinEvent -Path $Path -MaxEvents $MaxEvents
} else {
    Get-WinEvent -FilterHashtable @{LogName=$LogName;StartTime=$Since} -MaxEvents $MaxEvents
}
$writer = New-Object System.IO.StreamWriter([IO.Path]::GetFullPath($OutputFile),$false,(New-Object System.Text.UTF8Encoding($false)))
try {
    foreach ($event in $events) {
        [xml]$xml = $event.ToXml()
        $fields = @{}
        foreach ($item in $xml.Event.EventData.Data) {
            if ($item.Name) {$fields[[string]$item.Name] = [string]$item.InnerText}
        }
        $record = [ordered]@{
            EventID=$event.Id;TimeCreated=$event.TimeCreated.ToUniversalTime().ToString('o');
            Computer=$event.MachineName;Channel=$event.LogName;EventData=$fields
        }
        $writer.WriteLine(($record | ConvertTo-Json -Depth 12 -Compress))
    }
} finally {$writer.Dispose()}
Write-Output "Exported normalized Windows records to $OutputFile. Event truth labels are not inferred."
