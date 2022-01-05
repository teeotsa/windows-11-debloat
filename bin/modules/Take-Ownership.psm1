function Take-Ownership{
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateScript({Test-Path $_})]
        [String] $Path
    )

    takeown /f $Path /r | Out-Null
    icacls $Path /grant Everyone:F /Q /C /T | Out-Null
}

function Force-Remove{
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateScript({Test-Path $_})]
        [String] $Path
    )

    Take-Ownership -Path $Path
    Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
}