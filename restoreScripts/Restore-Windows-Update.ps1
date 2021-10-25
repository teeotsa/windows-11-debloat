If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}

# BITS     - Background Intelligent Transfer Service
# wuauserv - Windows Update
# appidsvc - Application Identity
# cryptsvc - Cryptographic Services

Stop-Service -Name BITS     
Stop-Service -Name wuauserv 
Stop-Service -Name appidsvc 
Stop-Service -Name cryptsvc 

$Path = "$env:allusersprofile\Application Data\Microsoft\Network\Downloader";
if(Test-Path $Path){
    Remove-Item "$Path\qmgr*.dat" -Force -ErrorAction SilentlyContinue | Out-Null
}

$SoftwareDistribution = "$env:systemroot\SoftwareDistribution";
$Catroot2 = "$env:systemroot\System32\Catroot2";
if(Test-Path $SoftwareDistribution){
    Rename-Item -Path $SoftwareDistribution -NewName "SoftwareDistribution.bak" -Force -ErrorAction SilentlyContinue | Out-Null
}
if(Test-Path $Catroot2){
    Rename-Item -Path $Catroot2 -NewName "Catroot2.bak" -Force -ErrorAction SilentlyContinue | Out-Null
}

Remove-Item "$env:systemroot\WindowsUpdate.log" -Force -ErrorAction SilentlyContinue | Out-Null
Set-Location "$env:systemroot\System32" 
regsvr32.exe /s atl.dll 
regsvr32.exe /s urlmon.dll 
regsvr32.exe /s mshtml.dll 
regsvr32.exe /s shdocvw.dll 
regsvr32.exe /s browseui.dll 
regsvr32.exe /s jscript.dll 
regsvr32.exe /s vbscript.dll 
regsvr32.exe /s scrrun.dll 
regsvr32.exe /s msxml.dll 
regsvr32.exe /s msxml3.dll 
regsvr32.exe /s msxml6.dll 
regsvr32.exe /s actxprxy.dll 
regsvr32.exe /s softpub.dll 
regsvr32.exe /s wintrust.dll 
regsvr32.exe /s dssenh.dll 
regsvr32.exe /s rsaenh.dll 
regsvr32.exe /s gpkcsp.dll 
regsvr32.exe /s sccbase.dll 
regsvr32.exe /s slbcsp.dll 
regsvr32.exe /s cryptdlg.dll 
regsvr32.exe /s oleaut32.dll 
regsvr32.exe /s ole32.dll 
regsvr32.exe /s shell32.dll 
regsvr32.exe /s initpki.dll 
regsvr32.exe /s wuapi.dll 
regsvr32.exe /s wuaueng.dll 
regsvr32.exe /s wuaueng1.dll 
regsvr32.exe /s wucltui.dll 
regsvr32.exe /s wups.dll 
regsvr32.exe /s wups2.dll 
regsvr32.exe /s wuweb.dll 
regsvr32.exe /s qmgr.dll 
regsvr32.exe /s qmgrprxy.dll 
regsvr32.exe /s wucltux.dll 
regsvr32.exe /s muweb.dll 
regsvr32.exe /s wuwebv.dll 

REG DELETE "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v AccountDomainSid /f 
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v PingID /f 
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v SusClientId /f 

netsh winsock reset 
netsh winhttp reset proxy 
 
Get-BitsTransfer | Remove-BitsTransfer 
$arch 

if($env:PROCESSOR_ARCHITECTURE -eq "AMD64"){ 
wusa Windows8-RT-KB2937636-x64 /quiet 
} else{ 
wusa Windows8-RT-KB2937636-x86 /quiet 
} 

Start-Service -Name BITS 
Start-Service -Name wuauserv 
Start-Service -Name appidsvc 
Start-Service -Name cryptsvc 
wuauclt /resetauthorization /detectnow 