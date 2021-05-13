# Win10PostInstall
Windows 10 Post Installation and Configuration script(s) for automating routine configuration tasks such as
- Deploying Local Group Policies
- Privacy Settings
- Regional Settings
- etc...

## Running
- Copy the repo to a suitable folder on your PC
- Edit the configuration files/scripts located under sub-folders as per requirements
- Type `.\Win10PostInstall.ps1` in Powershell

## Running as EXE
- The "Win10PostInstall.ps1" script and contents of "Bin" folder (zipped) can be converted into an EXE that can be executed without needing to run the script in Powershell.
- Type `.\ConvertToExe.ps1` in Powershell. This will create "Win10PostInstall.exe"
- Execute "Win10PostInstall.exe"
