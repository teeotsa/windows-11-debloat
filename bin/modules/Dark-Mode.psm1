function Dark-Mode{

    param(
        [Parameter(Mandatory = $false, ParameterSetName = "Enable Dark Mode")]
        [Switch] $Enable,

        [Parameter(Mandatory = $false, ParameterSetName = "Disable Dark Mode")]
        [Switch] $Disable
    )

    Switch($PSCmdlet.ParameterSetName){
    
        "Enable Dark Mode"{
            $Console = $Host.UI.RawUI
            $Console.Backgroundcolor = "Black"; $Console.Foregroundcolor = "White";
            Clear-Host
        }

        "Disable Dark Mode"{
            $Console = $Host.UI.RawUI
            $Console.Backgroundcolor = "Blue"; $Console.Foregroundcolor = "White";
            Clear-Host
        }

    }
}