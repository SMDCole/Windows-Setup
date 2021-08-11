#Setup script
#For setting up new PCs Remotely
#Created by Michael Bartlett
#Added to by Cole Bermudez
#For sole and exclusive use by SystemsMD
#Last updated: 3/19/2021



#initiates the variables required for the script 
$diskProps = (Get-PhysicalDisk | where size -gt 100gb)
$cortanaPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
$HighPerf = powercfg -l | %{if($_.contains("High performance")) {$_.split()[3]}}
$confirmUac = 'n'
$confirmInfo = 'n'
$confirmPower = 'n'
$confirmDev = 'n'
$avCheck = $false
$installCheck = 'n'
$officeCheck = $false

#Obtains required information, and prompts user to confirm
while ($confirmInfo -ne 'y') {
$compName = (Read-Host "Enter New Computer Name")
$userName = (Read-Host "Enter Admin Username")

Write-Output "`n`nComputer Name: $compName `nAdmin username: $userName`n"
$confirmInfo = (Read-Host "Is this information correct? Y/N")
}

#Asks user to set admin password, confirms it by comparing two passwords
# Credit to 'RowdyVinson' on stackoverflow
# https://stackoverflow.com/questions/38901752/verify-passwords-match-in-windows-powershell
do {
Write-Host "`nEnter Admin password"
    $pwd1 = Read-Host "Password" -AsSecureString
    $pwd2 = Read-Host "Confirm Password" -AsSecureString
    $pwd1_text = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwd1))
    $pwd2_text = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwd2))
    
    if ($pwd1_text -ne $pwd2_text) {
    Write-Warning "`nPasswords do not match. Please try again."
    }
}
while ($pwd1_text -ne $pwd2_text)
Write-Host "`n`nPasswords matched"
$userPass = $pwd1
$pwd1_text = 'a'
$pwd2_text = 'a'

#Sets computer name.
#Enables system restore on C:\
Write-Output "`n`nSetting computer name, and enabling system restore..."
Rename-Computer -NewName $compName
Enable-ComputerRestore -Drive "$env:SystemDrive"

#Disable sleep timers and create a restore point just in case
Write-Host "Disabling sleep and monitor timeout & setting timezone"
Write-Host "Creating Restore Point incase something bad happens"
Checkpoint-Computer -Description "RestorePoint1" -RestorePointType "MODIFY_SETTINGS"
Write-Host "Changing Power Settings"
powercfg.exe -change -monitor-timeout-ac 0
powercfg.exe -change -monitor-timeout-dc 0
powercfg.exe -change -disk-timeout-ac 0
powercfg.exe -change -disk-timeout-dc 0
powercfg.exe -change -standby-timeout-ac 0
powercfg.exe -change -standby-timeout-dc 0
powercfg.exe -change -hibernate-timeout-ac 0
powercfg.exe -change -hibernate-timeout-dc 0
Write-Host "Changing time zone to Mountain"
Set-TimeZone -Id "Mountain Standard Time"
Write-Host "Enabling .NET Framework"
Enable-WindowsOptionalFeature -Online -FeatureName NetFx3 -All

##########Essential Tweaks from Cole##########

#install Chocolatey and other programs
    Write-Host "Installing Chocolatey"
	Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
	choco install chocolatey-core.extension -y

#Install Automate & ScreenConnect (WIP)
	Write-Host "Installing Automate"
    #msiexec.exe /I C:\Agent_Install

#OO APP Buster
    Write-Host "Running O&O App Buster"
    $ProcName = "OOAPB.exe"
    $Webfile = "https://dl5.oo-software.com/files/ooappbuster/OOAPB.exe"
    (New-Object System.Net.WebClient).DownloadFile($WebFile, "$env:APPDATA\$ProcName")
    Start-Process ("$env:APPDATA\$ProcName")

#Install Java
    Write-Host "Installing Java SE Runtime Eviornment 8"
    choco install jre8 -y

#Install Firefox 
    Write-Host "Installing Firefox"
    choco install firefox -y

#Install Chrome 
    Write-Host "Installing Google Chrome"
    choco install googlechrome -y --ignore-checksums

#Install Adobe Reader 
    Write-Host "Installing Adobe Reader DC"
    choco install adobereader -y
    Write-Host "This will take some time..."

#Install 7-zip
    Write-Host "Installing 7-Zip Compression Tool"
    choco install 7zip -y

#Use O&O Shutup to automate a lot
	Write-Host "Running O&O Shutup with Recommended Settings"
    Import-Module BitsTransfer 
    choco install shutup10 -y
	Start-BitsTransfer -Source "https://raw.githubusercontent.com/SMDCole/Windows-Setup/main/ooshutup10.cfg" -Destination ooshutup10.cfg
	Start-BitsTransfer -Source "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -Destination OOSU10.exe	
	./OOSU10.exe ooshutup10.cfg /quiet

#Sets all NICs powersave and wake-on-lan modes correctly
Write-Output "`n`nConfiguring additional powersave options..."
Get-NetAdapter | where {$_.Name -like "*ethernet*" -or $_.Name -like '*wireless*' -or $_.Name -like '*Wi-Fi*'} | Set-NetAdapterPowerManagement -ArpOffload enabled -NSOffload enabled -DeviceSleepOnDisconnect disabled -SelectiveSuspend disabled -WakeOnMagicPacket enabled -WakeOnPattern enabled

    
    #Get Rid of nasty Windows stuff
    #Disables Windows Feedback Experience
    Write-Host "Disabling Windows Feedback Experience program"
    $Advertising = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
    If (Test-Path $Advertising) {
        Set-ItemProperty $Advertising Enabled -Value 0 
    }
            
    #Stops Cortana from being used as part of your Windows Search Function
    Write-Host "Stopping Cortana from being used as part of your Windows Search Function"
    $Search = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    If (Test-Path $Search) {
        Set-ItemProperty $Search AllowCortana -Value 0 
    }

    #Disables Web Search in Start Menu
    Write-Host "Disabling Bing Search in Start Menu"
    $WebSearch = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" BingSearchEnabled -Value 0 
	If (!(Test-Path $WebSearch)) {
        New-Item $WebSearch
	}
	Set-ItemProperty $WebSearch DisableWebSearch -Value 1 
            
    #Stops the Windows Feedback Experience from sending anonymous data
    Write-Host "Stopping the Windows Feedback Experience program"
    $Period = "HKCU:\Software\Microsoft\Siuf\Rules"
    If (!(Test-Path $Period)) { 
    New-Item $Period
    }
    Set-ItemProperty $Period PeriodInNanoSeconds -Value 0 

    #Prevents bloatware applications from returning and removes Start Menu suggestions               
    Write-Host "Adding Registry key to prevent bloatware apps from returning"
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    $registryOEM = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    If (!(Test-Path $registryPath)) { 
        New-Item $registryPath
    }
    Set-ItemProperty $registryPath DisableWindowsConsumerFeatures -Value 1 

    If (!(Test-Path $registryOEM)) {
        New-Item $registryOEM
    }
        Set-ItemProperty $registryOEM  ContentDeliveryAllowed -Value 0 
        Set-ItemProperty $registryOEM  OemPreInstalledAppsEnabled -Value 0 
        Set-ItemProperty $registryOEM  PreInstalledAppsEnabled -Value 0 
        Set-ItemProperty $registryOEM  PreInstalledAppsEverEnabled -Value 0 
        Set-ItemProperty $registryOEM  SilentInstalledAppsEnabled -Value 0 
        Set-ItemProperty $registryOEM  SystemPaneSuggestionsEnabled -Value 0          
    
    #Preping mixed Reality Portal for removal    
    Write-Host "Setting Mixed Reality Portal value to 0 so that you can uninstall it in Settings"
    $Holo = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic"    
    If (Test-Path $Holo) {
        Set-ItemProperty $Holo  FirstRunSucceeded -Value 0 
    }

    #Disables Wi-fi Sense
    Write-Host "Disabling Wi-Fi Sense"
    $WifiSense1 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting"
    $WifiSense2 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots"
    $WifiSense3 = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
    If (!(Test-Path $WifiSense1)) {
	    New-Item $WifiSense1
    }
    Set-ItemProperty $WifiSense1  Value -Value 0 
	If (!(Test-Path $WifiSense2)) {
	    New-Item $WifiSense2
    }
    Set-ItemProperty $WifiSense2  Value -Value 0 
	Set-ItemProperty $WifiSense3  AutoConnectAllowedOEM -Value 0 
        
    #Disables live tiles
    Write-Host "Disabling live tiles"
    $Live = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"    
    If (!(Test-Path $Live)) {      
        New-Item $Live
    }
    Set-ItemProperty $Live  NoTileApplicationNotification -Value 1 
        
    #Turns off Data Collection via the AllowTelemtry key by changing it to 0
    Write-Host "Turning off Data Collection"
    $DataCollection1 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
    $DataCollection2 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    $DataCollection3 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"    
    If (Test-Path $DataCollection1) {
        Set-ItemProperty $DataCollection1  AllowTelemetry -Value 0 
    }
    If (Test-Path $DataCollection2) {
        Set-ItemProperty $DataCollection2  AllowTelemetry -Value 0 
    }
    If (Test-Path $DataCollection3) {
        Set-ItemProperty $DataCollection3  AllowTelemetry -Value 0 
    }
    
    #Disabling Location Tracking
    Write-Host "Disabling Location Tracking"
    $SensorState = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
    $LocationConfig = "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration"
    If (!(Test-Path $SensorState)) {
        New-Item $SensorState
    }
    Set-ItemProperty $SensorState SensorPermissionState -Value 0 
    If (!(Test-Path $LocationConfig)) {
        New-Item $LocationConfig
    }
    Set-ItemProperty $LocationConfig Status -Value 0 
        
    #Disables People icon on Taskbar
    Write-Host "Disabling People icon on Taskbar"
    $People = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People"    
    If (!(Test-Path $People)) {
        New-Item $People
    }
    Set-ItemProperty $People  PeopleBand -Value 0 
        
    #Disables scheduled tasks that are considered unnecessary 
    Write-Host "Disabling scheduled tasks"
    Get-ScheduledTask  XblGameSaveTask | Disable-ScheduledTask
    Get-ScheduledTask  Consolidator | Disable-ScheduledTask
    Get-ScheduledTask  UsbCeip | Disable-ScheduledTask
    Get-ScheduledTask  DmClient | Disable-ScheduledTask
    Get-ScheduledTask  DmClientOnScenarioDownload | Disable-ScheduledTask
    
    Write-Host "Stopping and disabling WAP Push Service"
    #Stop and disable WAP Push Service
	Stop-Service "dmwappushservice"
	Set-Service "dmwappushservice" -StartupType Disabled

    Write-Host "Stopping and disabling Diagnostics Tracking Service"
    #Disabling the Diagnostics Tracking Service
	Stop-Service "DiagTrack"
	Set-Service "DiagTrack" -StartupType Disabled

    #Kill it...kill it with fire
    #Telemetry
    Write-Host "Disabling Telemetry..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
    
    #App suggestions
    Write-Host "Disabling Application suggestions..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
    Write-Host "Disabling Activity History..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
    Write-Host "Disabling Location Tracking..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
    Write-Host "Disabling automatic Maps updates..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
    Write-Host "Disabling Feedback..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
    Write-Host "Disabling Tailored Experiences..."
	If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
    Write-Host "Disabling Advertising ID..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1
    Write-Host "Disabling Error reporting..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
    Write-Host "Restricting Windows Update P2P only to local network..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null
	}
	#A lot more nasty stuff
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1
    Write-Host "Stopping and disabling Diagnostics Tracking Service..."
	Stop-Service "DiagTrack" -WarningAction SilentlyContinue
	Set-Service "DiagTrack" -StartupType Disabled
    Write-Host "Stopping and disabling WAP Push Service..."
	Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
	Set-Service "dmwappushservice" -StartupType Disabled
    Write-Host "Enabling F8 boot menu options..."
	bcdedit /set `{current`} bootmenupolicy Legacy | Out-Null
    Write-Host "Disabling Remote Assistance..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
    Write-Host "Disabling Storage Sense..."
	Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Recurse -ErrorAction SilentlyContinue
    Write-Host "Stopping and disabling Superfetch service..."
	Stop-Service "SysMain" -WarningAction SilentlyContinue
	Set-Service "SysMain" -StartupType Disabled
    Write-Host "Setting BIOS time to UTC..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -Type DWord -Value 1
    Write-Host "Disabling Hibernation..."
	Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernteEnabled" -Type Dword -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type Dword -Value 0
    Write-Host "Showing task manager details..."
	$taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru
	Do {
		Start-Sleep -Milliseconds 100
		$preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
	} Until ($preferences)
	Stop-Process $taskmgr
	$preferences.Preferences[28] = 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences
    Write-Host "Showing file operations details..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1
    Write-Host "Hiding Task View button..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
    Write-Host "Hiding People icon..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
    Write-Host "Showing all tray icons..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0
	Write-Host "Enabling NumLock after startup..."
	If (!(Test-Path "HKU:")) {
		New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
	}
	Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483650
	Add-Type -AssemblyName System.Windows.Forms
	If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
		$wsh = New-Object -ComObject WScript.Shell
		$wsh.SendKeys('{NUMLOCK}')
	}

    #Unpins all tiles from the Start Menu
    Write-Host "Unpinning all tiles from the start menu"
    (New-Object -Com Shell.Application).
    NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').
    Items() |
    %{ $_.Verbs() } |
    ?{$_.Name -match 'Un.*pin from Start'} |

    #Y this work but throw error?
    Write-Host "Changing default Explorer view to This PC"
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1
    
    Write-Host "Hiding 3D Objects icon from This PC..."
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue

    # Network Tweaks
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "IRPStackSize" -Type DWord -Value 20

	# SVCHost Tweak
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value 4194304

#Finally debloat all the visible stuff
$Bloatware = @(

        #Unnecessary Windows 10 AppX Apps
        "Microsoft.549981C3F5F10"
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
        "Microsoft.MixedReality.Portal"
        "Microsoft.People"
        "Microsoft.NetworkSpeedTest"
        "Microsoft.News"
        "Microsoft.Office.Lens"
        "Microsoft.Office.Sway"
        "Microsoft.OneConnect"
        "Microsoft.People"
        "Microsoft.Print3D"
        "Microsoft.SkypeApp"
        #"Microsoft.StorePurchaseApp"
        "Microsoft.Wallet"
        "Microsoft.Whiteboard"
        "Microsoft.WindowsAlarms"
        "Microsoft.windowscommunicationsapps"
        "Microsoft.WindowsFeedbackHub"
        "Microsoft.WindowsMaps"
        "Microsoft.WindowsSoundRecorder"
        "Microsoft.Xbox.TCUI"
        "Microsoft.XboxApp"
        "Microsoft.XboxGameOverlay"
        "Microsoft.XboxGamingOverlay"
        "Microsoft.XboxIdentityProvider"
        "Microsoft.XboxSpeechToTextOverlay"
        "Microsoft.YourPhone"
        "Microsoft.ZuneMusic"
        "Microsoft.ZuneVideo"

        #Sponsored Windows 10 AppX Apps
        #Add sponsored/featured apps to remove in the "*AppName*" format
        "*EclipseManager*"
        "*Amazon*"
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
        
        #If you're going for the grand slam debloat (You should)             
        #Optional: Typically not removed but you can if you need to for some reason
        "*Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe*"
        "*Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe*"
        "*Microsoft.BingWeather*"
        #"*Microsoft.MSPaint*"
        #"*Microsoft.MicrosoftStickyNotes*"
        #"*Microsoft.Windows.Photos*"
        #"*Microsoft.WindowsCalculator*"
        #"*Microsoft.WindowsStore*"
    )
    #Use list to remove AppX software
    foreach ($Bloat in $Bloatware) {
        Get-AppxPackage -AllUsers -Name $Bloat| Remove-AppxPackage
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online
        Write-Host "Trying to remove $Bloat."
    }

    #Install Media Player because Why not
    Write-Host "Installing Windows Media Player..."
    #Works outside Windows Sandbox.
	Enable-WindowsOptionalFeature -FeatureName "WindowsMediaPlayer" -All -Online -NoRestart -WarningAction SilentlyContinue | Out-Null

    #Stops edge from taking over as the default .PDF viewer    
    Write-Host "Stopping Edge from taking over as the default .PDF viewer"
	# Identify the edge application class 
	$Packages = "HKCU:SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages" 
	$edge = Get-ChildItem $Packages -Recurse -include "MicrosoftEdge" 
		
	# Specify the paths to the file and URL associations 
	$FileAssocKey = Join-Path $edge.PSPath Capabilities\FileAssociations 
	$URLAssocKey = Join-Path $edge.PSPath Capabilities\URLAssociations 
		
	# get the software classes for the file and URL types that Edge will associate 
	$FileTypes = Get-Item $FileAssocKey 
	$URLTypes = Get-Item $URLAssocKey 
		
	$FileAssoc = Get-ItemProperty $FileAssocKey 
	$URLAssoc = Get-ItemProperty $URLAssocKey 
		
	$Associations = @() 
	$Filetypes.Property | foreach {$Associations += $FileAssoc.$_} 
	$URLTypes.Property | foreach {$Associations += $URLAssoc.$_} 
		
	# add registry values in each software class to stop edge from associating as the default 
	foreach ($Association in $Associations) 
			{ 
			$Class = Join-Path HKCU:SOFTWARE\Classes $Association 
			#if (Test-Path $class) 
			#   {write-host $Association} 
			# Get-Item $Class 
			Set-ItemProperty $Class -Name NoOpenWith -Value "" 
			Set-ItemProperty $Class -Name NoStaticDefaultVerb -Value "" 
			}

    #Removes Paint3D stuff from context menu
$Paint3Dstuff = @(
        "HKCR:\SystemFileAssociations\.3mf\Shell\3D Edit"
	"HKCR:\SystemFileAssociations\.bmp\Shell\3D Edit"
	"HKCR:\SystemFileAssociations\.fbx\Shell\3D Edit"
	"HKCR:\SystemFileAssociations\.gif\Shell\3D Edit"
	"HKCR:\SystemFileAssociations\.jfif\Shell\3D Edit"
	"HKCR:\SystemFileAssociations\.jpe\Shell\3D Edit"
	"HKCR:\SystemFileAssociations\.jpeg\Shell\3D Edit"
	"HKCR:\SystemFileAssociations\.jpg\Shell\3D Edit"
	"HKCR:\SystemFileAssociations\.png\Shell\3D Edit"
	"HKCR:\SystemFileAssociations\.tif\Shell\3D Edit"
	"HKCR:\SystemFileAssociations\.tiff\Shell\3D Edit"
    )
    
    #Rename reg key to remove it, so it's revertible
    foreach ($Paint3D in $Paint3Dstuff) {
        If (Test-Path $Paint3D) {
	    $rmPaint3D = $Paint3D + "_"
	    Set-Item $Paint3D $rmPaint3D
	}
    }

#Disables some search like bing and indexing 
    Write-Host "Disabling Bing Search in Start Menu..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1
    Write-Host "Stopping and disabling Windows Search indexing service..."
	Stop-Service "WSearch" -WarningAction SilentlyContinue
	Set-Service "WSearch" -StartupType Disabled
    Write-Host "Hiding Taskbar Search icon / box..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0

#Cortana: Hi! I'm Cortana, and I'm here to help.
#Me: NOT FOR LONG HEATHEN!
    Write-Host "Disabling Cortana..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0


#Diable UAC and disable other Windows 'Security' 
    Write-Host "Lowering UAC level..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 0
#    Write-Host "Disabling Windows Defender..."
#	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender")) {
#		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Force | Out-Null
#	}
#	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1
#	If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
#		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -ErrorAction SilentlyContinue
#	} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 15063) {
#		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -ErrorAction SilentlyContinue
#	}
#   Write-Host "Disabling Windows Defender Cloud..."
#	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet")) {
#		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Force | Out-Null
#	}
#	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type DWord -Value 0
#	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type DWord -Value 2
    Write-Host "Disabling Meltdown (CVE-2017-5754) compatibility flag..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "cadca5fe-87d3-4b96-b7fb-a231484277cc" -ErrorAction SilentlyContinue
#   Write-Host "Disabling Malicious Software Removal Tool offering..."
#	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT")) {
#		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" | Out-Null
#	}
#	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -Type DWord -Value 1

#Set all security up
#    Write-Host "Raising UAC level..."
#	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5
#	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1
#   Write-Host "Disabling SMB 1.0 protocol..."
#	Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
#    Write-Host "Enabling Windows Defender..."
#	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
#	If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
#		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -Type ExpandString -Value "`"%ProgramFiles%\Windows Defender\MSASCuiL.exe`""
#	} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 15063) {
#		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -Type ExpandString -Value "`"%ProgramFiles%\Windows Defender\MSASCuiL.exe`""
#	}
#    Write-Host "Enabling Windows Defender Cloud..."
#	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -ErrorAction SilentlyContinue
#	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -ErrorAction SilentlyContinue
#   Write-Host "Disabling Windows Script Host..."
#	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Type DWord -Value 0
#    Write-Host "Enabling Meltdown (CVE-2017-5754) compatibility flag..."
#	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat")) {
#		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" | Out-Null
#	}
#	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "cadca5fe-87d3-4b96-b7fb-a231484277cc" -Type DWord -Value 0
#   Write-Host "Enabling Malicious Software Removal Tool offering..."
#	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -ErrorAction SilentlyContinue

#Normal Windows Update
    Write-Host "Enabling driver offering through Windows Update..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -ErrorAction SilentlyContinue
    Write-Host "Enabling Windows Update automatic restart..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -ErrorAction SilentlyContinue

#The necessary stuff from Windows Update
#    Write-Host "Disabling driver offering through Windows Update..."
#	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata")) {
#		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Force | Out-Null
#	}
#	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type DWord -Value 1
#	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching")) {
#		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Force | Out-Null
#	}
#	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -Type DWord -Value 1
#	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -Type DWord -Value 1
#	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -Type DWord -Value 0
#	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
#		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" | Out-Null
#	}
#	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1
#   Write-Host "Disabling Windows Update automatic restart..."
#	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
#		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
#	}
#	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value 1
#	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Type DWord -Value 0

#DONE