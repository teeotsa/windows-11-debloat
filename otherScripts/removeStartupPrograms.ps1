If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}
$StartupFolder = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run";
Remove-Item -Path $StartupFolder -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
New-Item -Path $StartupFolder -Force  -ErrorAction SilentlyContinue | Out-Null
$StartupFolder = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce";
Remove-Item -Path $StartupFolder -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
New-Item -Path $StartupFolder -Force  -ErrorAction SilentlyContinue | Out-Null
$StartupFolder = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
Remove-Item -Path $StartupFolder -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
New-Item -Path $StartupFolder -Force  -ErrorAction SilentlyContinue | Out-Null
$StartupFolder = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32";
Remove-Item -Path $StartupFolder -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
New-Item -Path $StartupFolder -Force  -ErrorAction SilentlyContinue | Out-Null
$StartupFolder = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder";
Remove-Item -Path $StartupFolder -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
New-Item -Path $StartupFolder -Force  -ErrorAction SilentlyContinue | Out-Null
$StartupFolder = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
Remove-Item -Path $StartupFolder -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
New-Item -Path $StartupFolder -Force  -ErrorAction SilentlyContinue | Out-Null
$StartupFolder = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce";
Remove-Item -Path $StartupFolder -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
New-Item -Path $StartupFolder -Force  -ErrorAction SilentlyContinue | Out-Null
$StartupFolder = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
Remove-Item -Path $StartupFolder -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
New-Item -Path $StartupFolder -Force  -ErrorAction SilentlyContinue | Out-Null
$StartupFolder = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32";
Remove-Item -Path $StartupFolder -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
New-Item -Path $StartupFolder -Force  -ErrorAction SilentlyContinue | Out-Null
$StartupFolder = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder";
Remove-Item -Path $StartupFolder -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
New-Item -Path $StartupFolder -Force  -ErrorAction SilentlyContinue | Out-Null
$StartupFolder = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run";
Remove-Item -Path $StartupFolder -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
New-Item -Path $StartupFolder -Force  -ErrorAction SilentlyContinue | Out-Null
$StartupFolder = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run";
Remove-Item -Path $StartupFolder -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
New-Item -Path $StartupFolder -Force  -ErrorAction SilentlyContinue | Out-Null
$StartupFolder = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run";
Remove-Item -Path $StartupFolder -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
New-Item -Path $StartupFolder -Force  -ErrorAction SilentlyContinue | Out-Null
$StartupFolder = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce";
Remove-Item -Path $StartupFolder -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
New-Item -Path $StartupFolder -Force  -ErrorAction SilentlyContinue | Out-Null