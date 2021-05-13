<#
.SYNOPSIS
    Shut-up / Configure privacy and anti-spy settings for Windows 10

.DESCRIPTION
  Configure privacy settings using OOSU10.exe on pre-configured file.
	Most settings are relevant for Windows 10 Pro.
	Windows 10 IoT Enterprise does not require / does not have such anti-privacy settings.
  
  OOSU10.exe is from https://www.oo-software.com/en/shutup10

.EXAMPLE
    .\ShutupWin10.ps1

#>

. $PSScriptRoot\OOSU10.exe ooshutup10.cfg /quiet
