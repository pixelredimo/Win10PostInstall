<#
.SYNOPSIS
    Load Local Group Policy Objects into Windows 10 PC

.DESCRIPTION
    Loads Machine and User Local Group Policy from pre-configured policy files using LGPO.exe

.EXAMPLE
    .\LoadGPO.ps1

#>

. $PSScriptRoot\LGPO.exe /m $PSScriptRoot\WinIoT-Machine-Registry.pol
. $PSScriptRoot\LGPO.exe /u $PSScriptRoot\WinIoT-User-Registry.pol

# check if User-Registry.pol settings have included Security Policy, if not uncomment below
# secedit.exe /configure /db %windir%\security\local.db /cfg $PSScriptRoot\WinIoT-SecurityPolicy.inf
