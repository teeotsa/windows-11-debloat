function TakeOwnership{
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Path
    )
    if (!(Test-Path $Path)){
        write-Warning "`"$Path`" does not exist!";
            return
    }

    takeown /f $Path /r | Out-Null
    $User = $env:USERNAME
    icacls $Path /grant Everyone:F /Q /C /T | Out-Null
}