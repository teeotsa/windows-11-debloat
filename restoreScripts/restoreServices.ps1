If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}
$DS = Get-Service | Where-Object{$_.StartType -eq "Disabled"}
foreach($Service in ($DS.Name)){
    Set-Service -Name $Service -StartupType Manual
}