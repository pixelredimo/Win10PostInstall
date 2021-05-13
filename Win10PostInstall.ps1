<#
  .SYNOPSIS
    Windows 10 Post Installation Configuration Script

  .DESCRIPTION
    Automates Windows 10 Configuration using a number of dependent script modules and programs.
    
    Running this script is best done on a fresh install on standalone PC, 
    because running it on pre-configured PC or Domain PC with GPO may result in errors occurring

  .EXAMPLE
    .\Win10PostInstall.ps1

	.NOTES
    - Requires Administrator privileges
    - To set execution policy to be able to run scripts only in the current PowerShell session use the following:
      Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

#>


# Check if running as Administrator and self elevate
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
	Write-Host "You didn't run this script as an Administrator. This script will self elevate to run as an Administrator and continue."
	Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
	Exit
}


Clear-Host
$Host.UI.RawUI.WindowTitle = 'Windows 10 Post Install Configuration Script'

# Execute the pre-configured Sophia script
. $PSScriptRoot\Bin\Sophia\Sophia.ps1

# Execute the pre-configured piowin script
. $PSScriptRoot\Bin\Pixel\Pixel.ps1

# Execute the pre-configured OO Shutup 10 script
# . $PSScriptRoot\Bin\OOSU10\ShutupWin10.ps1

# Execute the pre-configured Local Group Policies script
. $PSScriptRoot\Bin\LGPO\LoadGPO.ps1
