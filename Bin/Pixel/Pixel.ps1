<#
  .SYNOPSIS
    Default pre configured script file to use functions exported from the Pixel Module
  
  .DESCRIPTION
    Read carefully and configure the preset file before running.
    Running the script is best done on a fresh install because running it on pre-configured PC or Domain PC with GPO may result in errors occurring

  .EXAMPLE
    .\Pixel.ps1

	.NOTES
    - Requires Administrator privileges
    - To set execution policy to be able to run scripts only in the current PowerShell session use the following:
      Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

#>

$Host.UI.RawUI.WindowTitle = "Windows 10 Pixel Script"
Remove-Module -Name Pixel -Force -ErrorAction Ignore
Import-Module -Name $PSScriptRoot\Pixel.psd1 -PassThru -Force

<#
	.SYNOPSIS
	Adds the feature to run the script by specifying module functions as parameters

	.EXAMPLE
	.\Pixel.ps1 -Functions "ActivityHistory -Disable", InstallNetFx35

#>
if ($Functions)
{
	foreach ($Function in $Functions)
	{
		Invoke-Expression -Command $Function
	}
	exit
}

<#
	Enable script logging. The log will be being recorded into the script folder
	To stop logging just close the console or type "Stop-Transcript"
#>
Logging "C:\Temp"

# Create a restore point
# CreateRestorePoint

# Disable unnecessary Scheduled Tasks
DisableScheduledTasks @(
	"Consolidator",
	"FamilySafetyMonitor",
	"FamilySafetyRefreshTask",
	"Microsoft-Windows-DiskDiagnosticDataCollector",
	"MapsToastTask",
	"MapsUpdateTask",
	"ProgramDataUpdater",
	"Proxy",
	"UsbCeip",
	"XblGameSaveTask"
)

# Disable Services that can cause issues
#    SysMain: System analysis program causes high up to 100% CPU and DISK usage making pc unusable
#    wuauserv: Windows (Automatic) Update Service
DisableServices @(
	"SysMain",
	"wuauserv"
)

# Turn off User Activity Publishing/Uploading
ActivityHistory -Disable
# Turn on User Activity Publishing/Uploading
# ActivityHistory -Enable

# Turn off Action Notification Center
ActionCenter -Disable
# Turn on Action Notification Center
# ActionCenter -Enable

# Remove Unnecessary Windows 10 AppX Apps
RemoveBloatware

# Configure Regional Settings to United Kingdom
UKRegionalSettings

# Install .NET Framework 3.5 online (needs internet connection for successful installation)
# InstallNetFx35Online

# Remove Unused OEM Drivers 
# RemoveUnusedOEMDrivers

# Clean up Windows Components (operation takes a few hours, so run standalone if needed)
# CleanUpWindowsComponents

# Install Chocolatey (to silently install other applications such as Notepad++)
# InstallChocolatey

# Example User Group Settings
<#

AddLocalGroups @'
	Name, 			  Description
	Operators,	  "Operators Group"
	Supervisors,	"Supervisors Group"
	Engineers,	  "Engineers Group"
'@

AddLocalUsers @'
	UserName, 	FullName, 			    Password
	Operator,	  "Operator User",	  "xxx"
	Supervisor,	"Supervisor User",  "xxx"
	Engineer,	  "Engineer User",	  "xxx"
'@

AddLocalGroupMembers @'
	GroupName, 		MemberName
	Users,			  Operator
	Users,			  Supervisor
	Users,			  Engineer
	Operators,	  Operator
	Supervisors,	Supervisor
	Engineers,	  Engineer
	Administrators,	Engineers
'@

#>
