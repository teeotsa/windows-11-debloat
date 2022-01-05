If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
  Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
  Exit
}
Add-Type -AssemblyName System.Windows.Forms ; [System.Windows.Forms.Application]::EnableVisualStyles()

$Form = New-Object System.Windows.Forms.Form
$Form.Text = "Tweak Windows Defender"
$Form.StartPosition = "CenterScreen"
$Form.ClientSize = '700, 400'
$Form.FormBorderStyle = 'FixedSingle'

$DisableWindowsDefender = New-Object System.Windows.Forms.Button
$DisableWindowsDefender.Text = "Disable Windows Defender"
$DisableWindowsDefender.Width = 250
$DisableWindowsDefender.Height = 50
$DisableWindowsDefender.Location = New-Object System.Drawing.Point(20, 20)
$DisableWindowsDefender.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',12)
$Form.Controls.Add($DisableWindowsDefender)

$EnableWindowsDefender = New-Object System.Windows.Forms.Button
$EnableWindowsDefender.Text = "Enable Windows Defender"
$EnableWindowsDefender.Width = 250
$EnableWindowsDefender.Height = 50
$EnableWindowsDefender.Location = New-Object System.Drawing.Point(420, 20)
$EnableWindowsDefender.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',12)
$Form.Controls.Add($EnableWindowsDefender)

$DisableWindowsDefender.Add_Click({
  if(Test-Path "$PSScriptRoot\otherScripts\Disable-WindowsDefender.ps1"){
      $NSudo = "$PSScriptRoot\NSudo\NSudoLG.exe";
      $DisableScript = "$PSScriptRoot\otherScripts\Disable-WindowsDefender.ps1"
      Start-Process -FilePath $NSudo -ArgumentList "--U=T --P=E --ShowWindowMode=Hide Powershell -NoProfile -ExecutionPolicy Bypass -File `"$DisableScript`""
  }
})

$EnableWindowsDefender.Add_Click({
  if(Test-Path "$PSScriptRoot\otherScripts\Enable-WindowsDefender.ps1"){
    $NSudo = "$PSScriptRoot\NSudo\NSudoLG.exe";
    $DisableScript = "$PSScriptRoot\otherScripts\Enable-WindowsDefender.ps1"
    Start-Process -FilePath $NSudo -ArgumentList "--U=T --P=E --ShowWindowMode=Hide Powershell -NoProfile -ExecutionPolicy Bypass -File `"$DisableScript`""
  }
})

[Void] $Form.ShowDialog()