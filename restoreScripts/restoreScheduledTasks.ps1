$ErrorActionPreference = 'SilentlyContinue'
$wshell = New-Object -ComObject Wscript.Shell
$Button = [System.Windows.MessageBoxButton]::YesNoCancel
$ErrorIco = [System.Windows.MessageBoxImage]::Error
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}
cls
write-Host "This will take some time, please wait!"
$Task = Get-ScheduledTask
$TaskName = $Task.TaskName
foreach($s in $TaskName){
    Get-ScheduledTask -TaskName $s | Enable-ScheduledTask
}
exit

<#
cls
$Task = Get-ScheduledTask
$TaskName = $Task.TaskName
foreach($s in $TaskName){
    Get-ScheduledTask -TaskName $s | Enable-ScheduledTask
}
#>