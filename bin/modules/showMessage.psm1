function showInformation{
    param(
        [Parameter()]
        [string] $Title,

        [Parameter()]
        [string] $Message
    )
    if ($Title -eq $null){return}
    if ($Message -eq $null){return}
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show($Title, $Message, 'OK', [System.Windows.Forms.MessageBoxIcon]::Information)
}

function showWarning{
    param(
        [Parameter()]
        [string] $Title,

        [Parameter()]
        [string] $Message
    )
    if ($Title -eq $null){return}
    if ($Message -eq $null){return}
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show($Title, $Message, 'OK', [System.Windows.Forms.MessageBoxIcon]::Warning)
}

function showError{
    param(
        [Parameter()]
        [string] $Title,

        [Parameter()]
        [string] $Message
    )
    if ($Title -eq $null){return}
    if ($Message -eq $null){return}
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show($Title, $Message, 'OK', [System.Windows.Forms.MessageBoxIcon]::Error)
}