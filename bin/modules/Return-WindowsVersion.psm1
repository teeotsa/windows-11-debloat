function Return-WindowsVersion{
    [String] $ErrorActionPreference = "SilentlyContinue"
    [String] $RegistryPath          = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    [String] $RegistryKey           = "ProductName"
    [String] $Value                 = Get-ItemPropertyValue -Path $RegistryPath -Name $RegistryKey | Out-Null

    if(Get-ItemPropertyValue -Path $RegistryPath -Name $RegistryKey){
        Return (Get-ItemPropertyValue -Path $RegistryPath -Name $RegistryKey)
    }
}