function Test-RegistryValue {
    param (
     [parameter(Mandatory=$true)]
     [ValidateScript({Test-Path $_})]
     [ValidateNotNullOrEmpty()]$Path,

     [parameter(Mandatory=$true)]
     [ValidateNotNullOrEmpty()]$Value
    )
    try {
        Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction Stop | Out-Null
            return $true
    }
    catch {
        return $false
    }
}