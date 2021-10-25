<#
This custom PowerShell module was made by Teeotsa
Github : https://github.com/teeotsa

    Usage : 

        |
        * Display-Information -Title "<Your Title Here>" -Message "<Your Message Here>"
        |
        * Display-Warning -Title "<Your Title Here>" -Message "<Your Message Here>"
        |
        * Display-Error -Title "<Your Title Here>" -Message "<Your Message Here>"
        |

        NOTE : Don't leave "Title" or "Message" empty or you will get some errors




    Sources : 

        These websited listed below helped me alot!

            * https://docs.microsoft.com/en-us/dotnet/api/system.windows.forms.messagebox?view=windowsdesktop-5.0

            * https://docs.microsoft.com/en-us/dotnet/api/system.windows.forms.messagebox.show?view=windowsdesktop-5.0

            * https://www.c-sharpcorner.com/UploadFile/mahesh/understanding-message-box-in-windows-forms-using-C-Sharp/
#>

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

function Display-Information{
    param(
        [CmdletBinding()]
        [string] $Title,

        [CmdletBinding()]
        [string] $Message
    )

    $SystemTime = Get-Date -DisplayHint Time;
    if($SystemTime.Length -lt 1 -and $Message.Length -lt 1){
        Write-Host "ERROR : Hey! You can't display empty Information Message!" -ForegroundColor Red -BackgroundColor Black
            return
    }
    if($Message.Length -lt 1){
        Write-Host "$SystemTime : Hey! You can't display empty Information Message!" -ForegroundColor Red -BackgroundColor Black 
            return 
    }
    if($Title.Length -lt 1){
        Write-Host "$SystemTime : Hey! You can't have no title?!" -ForegroundColor Red -BackgroundColor Black 
            return 
    }

    $InformationMessageBoxButtons = [System.Windows.MessageBoxButton]::OK;
    $InformationMessageBoxIcon    = [System.Windows.MessageBoxImage]::Information;
    $InformationMessageBoxTitle   = $Title;
    $InformationMessageBoxMessage = $Message;
    [System.Windows.MessageBox]::Show($InformationMessageBoxMessage, $InformationMessageBoxTitle, $InformationMessageBoxButtons, $InformationMessageBoxIcon) | Out-Null
}

function Display-Warning{
    param(
        [CmdletBinding()]
        [string] $Title,

        [CmdletBinding()]
        [string] $Message
    )

    $SystemTime = Get-Date -DisplayHint Time;
    if($SystemTime.Length -lt 1 -and $Message.Length -lt 1){
        Write-Host "ERROR : Hey! You can't display empty Warning Message!" -ForegroundColor Red -BackgroundColor Black
            return
    }
    if($Message.Length -lt 1){
        Write-Host "$SystemTime : Hey! You can't display empty Warning Message!" -ForegroundColor Red -BackgroundColor Black 
            return 
    }
    if($Title.Length -lt 1){
        Write-Host "$SystemTime : Hey! You can't have no title?!" -ForegroundColor Red -BackgroundColor Black 
            return 
    }

    $WarningMessageBoxButtons = [System.Windows.MessageBoxButton]::OK;
    $WarningMessageBoxIcon    = [System.Windows.MessageBoxImage]::Warning;
    $WarningMessageBoxTitle   = $Title;
    $WarningMessageBoxMessage = $Message;
    [System.Windows.MessageBox]::Show($WarningMessageBoxMessage, $WarningMessageBoxTitle, $WarningMessageBoxButtons, $WarningMessageBoxIcon) | Out-Null
}

function Display-Error{
    param(
        [CmdletBinding()]
        [string] $Title,

        [CmdletBinding()]
        [string] $Message
    )

    $SystemTime = Get-Date -DisplayHint Time;
    if($SystemTime.Length -lt 1 -and $Message.Length -lt 1){
        Write-Host "ERROR : Hey! You can't display empty Error Message!" -ForegroundColor Red -BackgroundColor Black
            return
    }
    if($Message.Length -lt 1){
        Write-Host "$SystemTime : Hey! You can't display empty Error Message!" -ForegroundColor Red -BackgroundColor Black 
            return 
    }
    if($Title.Length -lt 1){
        Write-Host "$SystemTime : Hey! You can't have no title?!" -ForegroundColor Red -BackgroundColor Black 
            return 
    }

    $ErrorMessageBoxButtons = [System.Windows.MessageBoxButton]::OK;
    $ErrorMessageBoxIcon    = [System.Windows.MessageBoxImage]::Error;
    $ErrorMessageBoxTitle   = $Title;
    $ErrorMessageBoxMessage = $Message;
    [System.Windows.MessageBox]::Show($ErrorMessageBoxMessage, $ErrorMessageBoxTitle, $ErrorMessageBoxButtons, $ErrorMessageBoxIcon) | Out-Null
}