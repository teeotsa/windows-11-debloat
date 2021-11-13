If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}

Write-Host "If the script prompts you with the question, answer `"Yes`"" -ForegroundColor Yellow
Unregister-ScheduledTask -TaskName "Auto Time Sync" -ErrorAction SilentlyContinue | Out-Null
Pause