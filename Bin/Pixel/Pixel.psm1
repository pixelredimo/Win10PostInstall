<#
	.SYNOPSIS
	A PowerShell module exporting functions to configure Windows 10 and automating routine tasks
#>

<#
	Enable script logging. The log will be being recorded into the script folder
	To stop logging just close the console or type "Stop-Transcript"
#>
function Logging
{
    param
    (
	    [Parameter(Mandatory=$false)]
	    [String]
        $LogDirectoryPath 
    )
	
    if($LogDirectoryPath)
    {
		if(!(Test-Path $LogDirectoryPath))
		{
		  New-Item -ItemType Directory -Force -Path $LogDirectoryPath
		}
    } else {
      $LogDirectoryPath = $PSScriptRoot
	}

	$TrascriptFilename = "Log-Pixel-$((Get-Date).ToString("yyyyMMdd-HHmm"))"
	Start-Transcript -Path $LogDirectoryPath\$TrascriptFilename.txt -Force
}

# Create a restore point for the system drive
function CreateRestorePoint
{
	$SystemDriveUniqueID = (Get-Volume | Where-Object {$_.DriveLetter -eq "$($env:SystemDrive[0])"}).UniqueID
	$SystemProtection = ((Get-ItemProperty -ErrorAction Ignore -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SPP\Clients")."{09F7EDC5-294E-4180-AF6A-FB0E6A0E9513}") | Where-Object -FilterScript {$_ -match [regex]::Escape($SystemDriveUniqueID)}

	$ComputerRestorePoint = $false

	switch ($null -eq $SystemProtection)
	{
		$true
		{
			$ComputerRestorePoint = $true
			Enable-ComputerRestore -Drive $env:SystemDrive
		}
	}

	# Never skip creating a restore point
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name SystemRestorePointCreationFrequency -PropertyType DWord -Value 0 -Force

	Checkpoint-Computer -Description "Windows 10 poiwin Script" -RestorePointType MODIFY_SETTINGS

	# Revert the System Restore checkpoint creation frequency to 1440 minutes
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name SystemRestorePointCreationFrequency -PropertyType DWord -Value 1440 -Force

	# Turn off System Protection for the system drive if it was turned off without deleting existing restore points
	if ($ComputerRestorePoint)
	{
		Disable-ComputerRestore -Drive $env:SystemDrive
	}
}

<#
	.SYNOPSIS
	Do not use/use sign-in info to automatically finish setting up device and reopen apps after an update or restart

	.PARAMETER Disable
	Do not use sign-in info to automatically finish setting up device and reopen apps after an update or restart

	.PARAMETER Enable
	Use sign-in info to automatically finish setting up device and reopen apps after an update or restart

	.EXAMPLE
	SigninInfo -Disable

	.EXAMPLE
	SigninInfo -Enable

	.NOTES
	Current user only
#>
function SigninInfo
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Disable"
		{
			$SID = (Get-CimInstance -ClassName Win32_UserAccount | Where-Object -FilterScript {$_.Name -eq $env:USERNAME}).SID
			if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$SID"))
			{
				New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$SID" -Force
			}
			New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$SID" -Name OptOut -PropertyType DWord -Value 1 -Force
		}
		"Enable"
		{
			$SID = (Get-CimInstance -ClassName Win32_UserAccount | Where-Object -FilterScript {$_.Name -eq $env:USERNAME}).SID
			Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$SID" -Name OptOut -Force -ErrorAction SilentlyContinue
		}
	}
}

<#
	.SYNOPSIS
	Add Local Group accounts

	.PARAMETER GroupCsv
	CSV string table of GroupName, Description

	.EXAMPLE
	AddLocalGroups @'
    Name, 			Description
    Operators,	"Operators Group"
    Supervisors,	"Supervisors Group"
    Engineers,	"Engineers Group"
'@

	.EXAMPLE
	$groups = @'
    Name, 			Description
    Operators,	"Operators Group"
    Supervisors,	"Supervisors Group"
    Engineers,	"Engineers Group"
'@
  AddLocalGroups $groups

	.NOTES
	The CSV Table header should contain columns: Name, Description
	Words with spaces should be enclosed within quotes.
#>
function AddLocalGroups
{
	param
    (
	    [Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
	    [String]
        $GroupCsv 
	)

	$Groups = ConvertFrom-Csv $GroupCsv
	
	ForEach($Group in $Groups)
	{
		New-LocalGroup -Name $Group.Name -Description $Group.Description #-WhatIf
	}
}

<#
	.SYNOPSIS
	Add Local User accounts

	.PARAMETER UserCsv
	CSV string table of UserName, FullName, Password

	.EXAMPLE
	AddLocalUsers @'
    UserName, 	FullName, 			Password
    Operator,	"Operator User",	"xxx"
    Supervisor,	"Supervisor User",	"yyy"
    Engineer,	"Engineer User",	""
'@

	.EXAMPLE
	$users = @'
    UserName, 	FullName, 			Password
    Operator,	"Operator User",	"xxx"
    Supervisor,	"Supervisor User",	"yyy"
    Engineer,	"Engineer User",	""
'@
  AddLocalUsers $users

	.NOTES
	- The CSV Table header should contain columns: UserName, FullName, Password
	- Words with spaces should be enclosed within quotes.
  - If supplied Password is null or empty the User is created without a password
#>
function AddLocalUsers
{
	param
    (
	    [Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
	    [String]
        $UserCsv 
	)

	$Users = ConvertFrom-Csv $UserCsv
	
	ForEach($User in $Users)
	{
		$params = @{
			'Name' = $User.UserName
			'FullName' = $User.FullName
			'AccountNeverExpires' = $null
		}
		if([string]::IsNullOrWhiteSpace($User.Password))
		{
			$params['NoPassword'] = $null
		}
		else
		{
			$params['Password'] = ConvertTo-SecureString $User.Password -AsPlainText -Force
		}
		New-LocalUser @params #-WhatIf
	}
}

<#
	.SYNOPSIS
	Add Local Members to Group

	.PARAMETER GroupCsv
	CSV string table of GroupName, MemberName

	.EXAMPLE
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

	.EXAMPLE
	$groups = @'
    GroupName, 		MemberName
    Operators,	Operator
    Users,			Operators
'@
  AddLocalGroupMembers $groups

	.NOTES
	- The CSV Table header should contain columns: GroupName, MemberName
	- Words with spaces should be enclosed within quotes.
  - The Group and the individual Member must already exist, else a NullReferenceException will be reported.
#>
function AddLocalGroupMembers
{
	param
    (
	    [Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
	    [String]
        $GroupCsv 
	)

	$Groups = ConvertFrom-Csv $GroupCsv
	
	ForEach($Group in $Groups)
	{
		Add-LocalGroupMember -Group $Group.GroupName -Member $Group.MemberName #-WhatIf
	}
}

<#
	.SYNOPSIS
	Disable Scheduled Tasks

	.PARAMETER Tasks
	string array of task names

	.EXAMPLE
	DisableScheduledTasks @(
    "ProgramDataUpdater",
    "Proxy"
)

	.EXAMPLE
	$Tasks = @(
    "ProgramDataUpdater",
    "Proxy",
    "Consolidator",
    "UsbCeip",
    "Microsoft-Windows-DiskDiagnosticDataCollector",
    "MapsToastTask",
    "MapsUpdateTask",
    "FamilySafetyMonitor",
    "FamilySafetyRefreshTask",
    "XblGameSaveTask"
)
  DisableScheduledTasks $Tasks

#>
function DisableScheduledTasks
{
    param
    (
        [Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
        [string[]]
        $Tasks
    )

    ForEach($task in $Tasks)
    {
        Get-ScheduledTask -TaskName $task | Disable-ScheduledTask 
    }
}

<#
	.SYNOPSIS
	Disable Services

	.PARAMETER Tasks
	string array of service names (SERVICE_NAME from SC QUERY)

	.EXAMPLE
	DisableServices @(
    "SysMain",
    "wuauserv"
)

	.EXAMPLE
	$Services = @(
    "SysMain",
    "wuauserv"
)
  DisableServices $Services

#>
function DisableServices
{
    param
    (
        [Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
        [string[]]
        $Services
    )

    ForEach($service in $Services)
    {
        Stop-Service -Name $service -Force
        Set-Service -Name $service -StartupType Disabled
    }
}

<#
	.SYNOPSIS
	Configure User Activity Publishing/Uploading

	.PARAMETER Disable
	Turn off User Activity Publishing/Uploading

	.PARAMETER Enable
	Turn on User Activity Publishing/Uploading

	.EXAMPLE
	ActivityHistory -Disable

	.EXAMPLE
	ActivityHistory -Enable

	.NOTES
	Machine-wide
#>
function ActivityHistory
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Disable"
		{
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
		}
		"Enable"
		{
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 1
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 1
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 1
		}
	}
}

<#
	.SYNOPSIS
	Configure Action Notification Center

	.PARAMETER Disable
	Turn off Action Notification Center

	.PARAMETER Enable
	Turn on Action Notification Center

	.EXAMPLE
	ActionCenter -Disable

	.EXAMPLE
	ActionCenter -Enable

	.NOTES
	Machine-wide
#>
function ActionCenter
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Disable"
		{
			If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
				New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
			}
			Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value 1
			Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 0
		}
		"Enable"
		{
			Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value 0
			Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 1
		}
	}
}

<#
	.SYNOPSIS
	Configure automatic windows update that includes cummulative, security, feature etc...

	.PARAMETER Enable
	Enable Automatic Windows Update 

	.PARAMETER Disable
	Disable Automatic Windows Update permanently

	.EXAMPLE
	AutomaticWindowsUpdate -Enable

	.EXAMPLE
	AutomaticWindowsUpdate -Disable

	.NOTES
	Machine-wide
	Use Disable option with caution and only under specific situations when no automatic updates are required.
	Manual updates are still possible when disabled.
#>
function AutomaticWindowsUpdate
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Remove-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Force -ErrorAction SilentlyContinue
		}
		"Disable"
		{
			if (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU))
			{
				New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Force
			}
			New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name NoAutoUpdate -PropertyType DWord -Value 1 -Force
		}
	}
}

<#
	.SYNOPSIS
	Configure Internet Protocol version 6 - TCP/IPv6 Network Setting across all Network Adapters

	.PARAMETER Enable
	Enable TCP/IPv6 across all Network Adapters

	.PARAMETER Disable
	Disable TCP/IPv6 across all Network Adapters

	.EXAMPLE
	TCPIPv6 -Enable

	.EXAMPLE
	TCPIPv6 -Disable

	.NOTES
	Machine-wide
#>
function TCPIPv6
{
	param
	(
		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Enable"
		)]
		[switch]
		$Enable,

		[Parameter(
			Mandatory = $true,
			ParameterSetName = "Disable"
		)]
		[switch]
		$Disable
	)

	switch ($PSCmdlet.ParameterSetName)
	{
		"Enable"
		{
			Remove-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters -Name DisabledComponents -Force -ErrorAction SilentlyContinue
		}
		"Disable"
		{
			New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters -Name DisabledComponents -PropertyType DWord -Value 255 -Force
		}
	}
}


# Install Chocolatey (to silently install other applications such as Notepad++)
function InstallChocolatey
{
	Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
	choco install chocolatey-core.extension -y
}

# Install .NET Framework 3.5 from online Windows Update - needs internet connection
function InstallNetFx35Online
{
	DISM /Online /Enable-Feature /FeatureName:NetFx3 /All
}


# Remove Unnecessary Windows 10 AppX Apps
function RemoveBloatware
{
$Bloatware = @(

        #Unnecessary Windows 10 AppX Apps
        "Microsoft.3DBuilder"
        "Microsoft.AppConnector"
        "Microsoft.BingFinance"
        "Microsoft.BingNews"
        "Microsoft.BingSports"
        "Microsoft.BingTranslator"
        "Microsoft.BingWeather"
        "Microsoft.GetHelp"
        "Microsoft.Getstarted"
        "Microsoft.Messaging"
        "Microsoft.Microsoft3DViewer"
        "Microsoft.MicrosoftSolitaireCollection"
        "Microsoft.NetworkSpeedTest"
        "Microsoft.News"
        "Microsoft.Office.Lens"
        "Microsoft.Office.Sway"
        "Microsoft.OneConnect"
        "Microsoft.People"
        "Microsoft.Print3D"
        "Microsoft.SkypeApp"
        "Microsoft.StorePurchaseApp"
        "Microsoft.Wallet"
        "Microsoft.Whiteboard"
        "Microsoft.WindowsAlarms"
        "microsoft.windowscommunicationsapps"
        "Microsoft.WindowsFeedbackHub"
        "Microsoft.WindowsMaps"
        "Microsoft.WindowsSoundRecorder"
        "Microsoft.ZuneMusic"
        "Microsoft.ZuneVideo"

        #Sponsored Windows 10 AppX Apps
        #Add sponsored/featured apps to remove in the "*AppName*" format
        "*EclipseManager*"
        "*ActiproSoftwareLLC*"
        "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
        "*Duolingo-LearnLanguagesforFree*"
        "*PandoraMediaInc*"
        "*CandyCrush*"
        "*BubbleWitch3Saga*"
        "*Wunderlist*"
        "*Flipboard*"
        "*Twitter*"
        "*Facebook*"
        "*Royal Revolt*"
        "*Sway*"
        "*Speed Test*"
        "*Dolby*"
        "*Viber*"
        "*ACGMediaPlayer*"
        "*Netflix*"
        "*OneCalendar*"
        "*LinkedInforWindows*"
        "*HiddenCityMysteryofShadows*"
        "*Hulu*"
        "*HiddenCity*"
        "*AdobePhotoshopExpress*"
                     
        #Optional: Typically not removed but you can if you need to for some reason
        #"*Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe*"
        #"*Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe*"
        #"*Microsoft.BingWeather*"
        #"*Microsoft.MSPaint*"
        #"*Microsoft.MicrosoftStickyNotes*"
        #"*Microsoft.Windows.Photos*"
        #"*Microsoft.WindowsCalculator*"
        #"*Microsoft.WindowsStore*"
    )
	
    foreach ($Bloat in $Bloatware) {
        Get-AppxPackage -Name $Bloat| Remove-AppxPackage
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online
    }	
}

<#
	.SYNOPSIS
	Remove Unused OEM Drivers 
	(especially useful on Windows IoT)
#>
function RemoveUnusedOEMDrivers
{
	for ($i=1; $i -le 600; $i++) 
	{ 
		Write-Host "Deleting Driver OEM$i.inf" 
		pnputil /d OEM$i.INF
	}
}

<#
	.SYNOPSIS
	Clean up Windows Components 
	(useful when C:\Windows\WinSxS folders grows due to updates)

	.NOTES
	To analyse space taken run the following command
	dism /Online /Cleanup-Image /AnalyzeComponentStore
#>
function CleanUpWindowsComponents
{
	dism /online /Cleanup-Image /StartComponentCleanup
}

<#
	.SYNOPSIS
	Configure Regional Settings (Locale, TimeZone, Language) to United Kingdom

	.NOTES
	To analyse space taken run the following command
	dism /Online /Cleanup-Image /AnalyzeComponentStore
#>
function UKRegionalSettings
{
  # The following don't affect the default user account
  Set-WinSystemLocale -SystemLocale en-GB
  Set-WinHomeLocation -GeoId 242
  Set-WinUserLanguageList -LanguageList (New-WinUserLanguageList -Language en-GB) -Force

  # Set Locale, language etc. 
  & $env:SystemRoot\System32\control.exe "intl.cpl,,/f:`"`$PSScriptRoot\UKRegion.xml`""

  # Set Timezone
  & tzutil /s "GMT Standard Time"

  # Set languages/culture
  Set-Culture en-GB 

}

