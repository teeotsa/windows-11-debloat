If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}

$Items = Get-ChildItem -Path (Join-Path -Path $PSScriptRoot -ChildPath "restoreScripts") 
$Items | ForEach-Object{
    if($_.Extension -match "reg"){
        Invoke-Command -ScriptBlock {
            reg.exe import $_.FullName
        }
    }
    if($_.Extension -match "ps1"){
        Invoke-Command -ScriptBlock {
            $File = $_.FullName
            Start-Process -FilePath "powershell" -ArgumentList " -NoProfile -AsJob -ExecutionPolicy Bypass -File `"$File`"" -Verb RunAs -WindowStyle Hidden
        }
    }
}
Pause