Set-Service -StartupType Automatic "WinDefend" -ErrorAction SilentlyContinue | Out-Null
Start-Service -Force -Name "WinDefend" -ErrorAction SilentlyContinue | Out-Null
Set-Service -StartupType Automatic "WdNisSvc" -ErrorAction SilentlyContinue | Out-Null
Start-Service -Force -Name "WdNisSvc" -ErrorAction SilentlyContinue | Out-Null
Set-Service -StartupType Automatic "mpssvc" -ErrorAction SilentlyContinue | Out-Null
Start-Service -Force -Name "mpssvc" -ErrorAction SilentlyContinue | Out-Null
Set-Service -StartupType Automatic "Sense" -ErrorAction SilentlyContinue | Out-Null
Start-Service -Force -Name "Sense" -ErrorAction SilentlyContinue | Out-Null
Set-Service -StartupType Automatic "wscsvc" -ErrorAction SilentlyContinue | Out-Null
Start-Service -Force -Name "wscsvc" -ErrorAction SilentlyContinue | Out-Null
Set-Service -Name SecurityHealthService -StartupType Automatic -ErrorAction SilentlyContinue | Out-Null
Start-Service -Name SecurityHealthService -ErrorAction SilentlyContinue | Out-Null
Enable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" | Out-Null
Enable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup" | Out-Null
Enable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" | Out-Null
Enable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Defender\Windows Defender Verification" | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SecurityHealthService" -Name Start -Value 2