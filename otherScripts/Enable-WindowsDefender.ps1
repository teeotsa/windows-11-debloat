Set-Service -Name "WinDefend" -StartupType Automatic -ErrorAction SilentlyContinue | Out-Null
Set-Service -Name "mpssvc" -StartupType Automatic -ErrorAction SilentlyContinue | Out-Null
Set-Service -Name "Sense" -StartupType Automatic -ErrorAction SilentlyContinue | Out-Null
Set-Service -Name "wscsvc" -StartupType Automatic -ErrorAction SilentlyContinue | Out-Null
Set-Service -Name "WdNisSvc" -StartupType Automatic -ErrorAction SilentlyContinue | Out-Null
Set-Service -Name "SecurityHealthService" -StartupType Automatic -ErrorAction SilentlyContinue | Out-Null
Start-Service -Name "WdNisSvc" -ErrorAction SilentlyContinue | Out-Null
Start-Service -Name "WinDefend" -ErrorAction SilentlyContinue | Out-Null
Start-Service -Name "mpssvc" -ErrorAction SilentlyContinue | Out-Null
Start-Service -Name "wscsvc" -ErrorAction SilentlyContinue | Out-Null
Start-Service -Name "Sense" -ErrorAction SilentlyContinue | Out-Null
Start-Service -Name SecurityHealthService -ErrorAction SilentlyContinue | Out-Null
Enable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" | Out-Null
Enable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup" | Out-Null
Enable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" | Out-Null
Enable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Defender\Windows Defender Verification" | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SecurityHealthService" -Name Start -Value 2
if (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications")){
    New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoTileApplicationNotification" -Type DWord -Value 0