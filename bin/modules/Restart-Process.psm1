function Restart-Process{
    param(
        [Parameter(Mandatory = $True)]
        [ValidateScript({Get-Process -Name $_})]
        [String] $Process,

        [Parameter(Mandatory = $False)]
        [Switch] $Restart,

        [Parameter(Mandatory = $False)]
        [Int] $RestartDelay = 5
    )
    $ProcessPath = (Get-Process -Name $Process).Path
    Stop-Process -Name $Process.ToString() -Force -ErrorAction SilentlyContinue | Out-Null

    if(($ProcessPath -ne $null) -and ($Restart)){
        Start-Sleep -Seconds $RestartDelay
        
        if(!(Get-Process -Name $Process -ErrorAction SilentlyContinue)){
            Start-Process -FilePath $ProcessPath -Verb RunAs -ErrorAction SilentlyContinue | Out-Null
        }
    }
}