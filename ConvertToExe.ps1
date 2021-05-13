<#
.SYNOPSIS
  Convert Powershell script to EXE including sub-folder
  
.DESCRIPTION
  Package the main powershell script along with sub-folder into EXE.
  
  Uses Create-EXEFromPS1 : https://github.com/onepixelzero/Create-EXEFromPS1

.EXAMPLE
  .\ConvertToExe.ps1 

#>

# import module containing New-EXEFromPS1
Import-Module Create-EXEFromPS1 -PassThru -Force

# convert the script and dependencies to EXE
New-EXEFromPS1 -PSScriptPath $PSScriptRoot\Win10PostInstall.ps1 -SupplementalDirectoryPath $PSScriptRoot\Bin

pause
