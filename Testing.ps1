If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}

if(Test-Path "$PSScriptRoot\otherScripts\Disable-WindowsDefender.ps1"){
    $NSudo = "$PSScriptRoot\NSudo\NSudoLG.exe";
    $DisableScript = "$PSScriptRoot\otherScripts\Disable-WindowsDefender.ps1"
    Start-Process -FilePath $NSudo -ArgumentList "--U=T --P=E --ShowWindowMode=Hide Powershell -NoProfile -ExecutionPolicy Bypass -File `"$DisableScript`""
}