If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}

Write-Host "Trying to remove batch script..." -ForegroundColor Yellow
Remove-Item -Path "$env:SystemRoot\StartService.bat" -Force -ErrorAction SilentlyContinue | Out-Null

Write-Host "Removing Registry Key..." -ForegroundColor Yellow
$Key = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name StartTabletInputService
if($Key){
  Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name StartTabletInputService -Force -ErrorAction SilentlyContinue | Out-Null
}

Write-Host "Done! Please exit this script now...!" -ForegroundColor Green
Pause