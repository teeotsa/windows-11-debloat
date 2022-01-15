If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}

$Icon = [System.Windows.Forms.MessageBoxIcon]::Question
$Buttons = [System.Windows.Forms.MessageBoxButtons]::YesNo
$Title = "Remove startup programs!"
$Message = "Do you wish to remove ALL startup programs? Might break certain applications!"
$Answer = [System.Windows.Forms.MessageBox]::Show($Message, $Title, $Buttons, $Icon)
if($Answer -match "Yes"){
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
	$Startup = "$env:SystemDrive\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
	foreach($Item in (Get-ChildItem -Path $Startup -Force -Recurse)){
		Remove-Item -Path (Join-Path -Path $Startup -ChildPath $Item)
	}
}

Exit