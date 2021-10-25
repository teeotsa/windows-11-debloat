<#
This custom module was created by Teeotsa
Github : https://github.com/teeotsa

Usage : 

    | -Path : First argument, used to feed in folder path
    |
    | -FolderName : Second argument, used to feed in folder name
    |
    Dont leave args empty or error will be prompted


Example : 

    New-Folder -Path "C:\" -FolderName "Example"


    These will give you errors :                 
    |
    |    New-Folder -Path "" -FolderName "Example"
    |
    |    New-Folder -Path "C:\" -FolderName ""
    |
    |    New-Folder -Path "" -FolderName ""
#>

function New-Folder{
    param(
        [CmdLetBinding()]
        [string] $Path,

        [CmdLetBinding()]
        [string] $FolderName
    )

    $SystemTime = Get-Date -DisplayHint Time

    if($Path.Length -lt 1 -or $FolderName.Length -lt 1){
        Write-Host "$SystemTime :|: Hey, check your function!" -ForegroundColor Red -BackgroundColor Black
            return
    }

    $FinalPath = $Path + $FolderName
    

    if(Test-Path $FinalPath){
        Write-Host "$SystemTime :|: This directory already exists! `"$FinalPath`"" -ForegroundColor Yellow -BackgroundColor Black
            return
    }

    New-Item -Path $FinalPath -ItemType Directory -Force | Out-Null
    Write-Host "$SystemTime :|: New directory created `"$FinalPath`"" -ForegroundColor Green -BackgroundColor Black;
}

