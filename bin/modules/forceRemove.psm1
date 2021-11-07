<#

    This module can break your system when used wrong!

#>

function Take-Ownership{
    [CmdletBinding()]
    param(
        [Parameter()]
        [string] $Path
    )
    if ($Path.Length -lt 1){
        $SystemTime = Get-Date -DisplayHint Time
        Write-Host "$SystemTime | Hey! You can't input empty path!" -ForegroundColor Red
        return;
    }
    if (!(Test-Path $Path)){
        $SystemTime = Get-Date -DisplayHint Time
        Write-Host "$SystemTime | Can't find path!" -ForegroundColor Red
        return;
    }
    takeown /f $Path /r | Out-Null
    $User = $env:USERNAME
    icacls $Path /grant Everyone:F /Q /C /T | Out-Null
}