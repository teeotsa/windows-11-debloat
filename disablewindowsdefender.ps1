If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}

$NSudoFolder = "$PSScriptRoot\NSudo";
if (!(Test-Path $NSudoFolder)){
    Write-Warning "`"$NSudoFolder`" does not exist! Because of this, script can't disable Windows Defender"
    Start-Sleep -Seconds 5
    exit;
}

$Commands = @(
    "Set-Service -StartupType Disabled 'WinDefend' -ErrorAction SilentlyContinue"
    "Stop-Service -Force -Name 'WinDefend' -ErrorAction SilentlyContinue"
    "Set-Service -StartupType Disabled 'WdNisSvc' -ErrorAction SilentlyContinue"
    "Stop-Service -Force -Name 'WdNisSvc' -ErrorAction SilentlyContinue"
    "Set-Service -StartupType Disabled 'mpssvc' -ErrorAction SilentlyContinue"
    "Stop-Service -Force -Name 'mpssvc' -ErrorAction SilentlyContinue"
    "Set-Service -StartupType Disabled 'Sense' -ErrorAction SilentlyContinue"
    "Stop-Service -Force -Name 'Sense' -ErrorAction SilentlyContinue"
    "Set-Service -StartupType Disabled 'wscsvc' -ErrorAction SilentlyContinue"
    "Stop-Service -Force -Name 'wscsvc' -ErrorAction SilentlyContinue"
    "Disable-ScheduledTask -TaskName '\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance' | Out-Null"
    "Disable-ScheduledTask -TaskName '\Microsoft\Windows\Windows Defender\Windows Defender Cleanup' | Out-Null"
    "Disable-ScheduledTask -TaskName '\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan' | Out-Null"
    "Disable-ScheduledTask -TaskName '\Microsoft\Windows\Windows Defender\Windows Defender Verification' | Out-Null"
)

foreach($CMD in $Commands){
    Start-Process -FilePath "$NSudoFolder\NSudoLG.exe" -ArgumentList "--U=T --P=E --ShowWindowMode=Hide powershell $CMD"
}
