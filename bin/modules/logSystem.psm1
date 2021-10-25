<#
    This custom PowerShell module was made by Teeotsa
    Github : https://github.com/teeotsa


        Usage : 

            ' Log-Success ' : Use this cmdlet to disaply Success messages
            ' Log-Warning ' : Use this cmdlet to display Warning messages
            ' Log-Error ' : Use this cmdlet to display Error messages

            Log-Success -SuccessMessage "<Your Success Message Here>"

            Log-Warning -WarningMessage "<Your Warning Message Here>"

            Log-Error -ErrorMessage "<Your Error Message Here>"


        Example : 

            Log-Success -SuccessMessage "Folder access granted!";

            Log-Warning -WarningMessage "Can't find this file, please re-create it!";

            Log-Error -ErrorMessage "Can't import this module!";

#>

function Log-Success{
    param(
        [CmdletBinding()]
        [String] $SuccessMessage
    )
    $SystemTime = Get-Date -DisplayHint Time;
    if($SuccessMessage.Length -lt 1){
        Write-Host "$SystemTime : Hey! You can't display empty Success Message!!!" -ForegroundColor Red -BackgroundColor Black
            return
    }
    if($SystemTime.Length -lt 1){
        Write-Host "SUCESS : $SuccessMessage" -ForegroundColor Green -BackgroundColor Black;
            return
    }
    Write-Host "$SystemTime : $SuccessMessage"  -ForegroundColor Green -BackgroundColor Black;
}

function Log-Warning{
    param(
        [CmdletBinding()]
        [String] $WarningMessage
    )
    $SystemTime = Get-Date -DisplayHint Time;
    if($WarningMessage.Length -lt 1){
        Write-Host "$SystemTime : Hey! You can't display empty Warning Message!!!" -ForegroundColor Red -BackgroundColor Black
            return
    }
    if($SystemTime.Length -lt 1){
        Write-Host "WARNING : $WarningMessage" -ForegroundColor Yellow -BackgroundColor Black;
            return
    }
    Write-Host "$SystemTime : $WarningMessage"  -ForegroundColor Yellow -BackgroundColor Black;
}

function Log-Error{
    param(
        [CmdletBinding()]
        [String] $ErrorMessage
    )
    $SystemTime = Get-Date -DisplayHint Time;
    if($ErrorMessage.Length -lt 1){
        Write-Host "$SystemTime : Hey! You can't display empty Error Message!!!" -ForegroundColor Red -BackgroundColor Black
            return
    }
    if($SystemTime.Length -lt 1){
        Write-Host "ERROR : $ErrorMessage" -ForegroundColor Red -BackgroundColor Black;
            return
    }
    Write-Host "$SystemTime : $ErrorMessage"  -ForegroundColor Red -BackgroundColor Black;
}