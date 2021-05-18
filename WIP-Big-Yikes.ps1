Function Install-Automate {
<#
.SYNOPSIS
    This PowerShell Function is for Automate Deployments
.DESCRIPTION
    Install the Automate Agent.
    
    This function will qualIfy the If another Autoamte agent is already 
    installed on the computer. If the existing agent belongs to dIfferent 
    Automate server, it will automatically "Rip & Replace" the existing 
    agent. This comparison is based on the server's FQDN. 
    
    This function will also verIfy If the existing Automate agent is 
    checking-in. The Confirm-Automate Function will verIfy the Server 
    address, LocationID, and Heartbeat/Check-in. If these entries are 
    missing or not checking-in properly; this function will automatically 
    attempt to restart the services, and then "Rip & Replace" the agent to 
    remediate the agent. 
    
    $Automate 
    $Global:Automate
    The output will be saved to $Automate as an object to be used in other functions.
    
    Example:
    Install-Automate -Server YOURSERVER.DOMAIN.COM -LocationID 2 -Transcript
    
    
    Tested OS:      Windows XP (with .Net 3.5.1 and PowerShell installed)
                    Windows Vista
                    Windows 7
                    Windows 8
                    Windows 10
                    Windows 2003R2
                    Windows 2008R2
                    Windows 2012R2
                    Windows 2016
                    Windows 2019
.PARAMETER Server
    This is the URL to your Automate server.
    
        Install-Automate -Server 'server.hostedrmm.com' -LocationID 2
.PARAMETER LocationID
    Use LocationID to install the Automate Agent directly to the appropieate client's location / site.
    If parameter is not specIfied, it will automatically assign LocationID 1 (New Computers).
.PARAMETER Token
    Use Token to install the Automate Agent directly to the appropieate client's location / site.
    If parameter is not specIfied, it will automatically attempt to use direct unauthenticated downloads.
    This method in blocked after Automate v20.0.6.178 (Patch 6)
    
.PARAMETER Force
    This will force the Automate Uninstaller prior to installation.
    Essentually, this will be a fresh install and a fresh check-in to the Automate server.
    
        Install-Automate -Server 'server.hostedrmm.com' -LocationID 2 -Force
.PARAMETER Silent
    This will hide all output (except a failed installation when Exit Code -ne 0)
    The function will exit once the installer has completed.
        
        Install-Automate -Server 'server.hostedrmm.com' -LocationID 2 -Silent
    
.PARAMETER Transcript
    This parameter will save the entire transcript and responsed to:
    $($env:windir)\Temp\AutomateLogon.txt
        
        Install-Automate -Server 'server.hostedrmm.com' -LocationID 2 -Transcript -Verbose
.LINK
    https://github.com/Braingears/PowerShell
    
.NOTES
    Version        : 1.0
    Author         : Chuck Fowler
    Creation Date  : 08/2019
    Purpose/Change : Initial script development
    
    Version        : 1.1
    Date           : 11/15/2019
    Changes        : Add $Automate.InstFolder and $Automate.InstRegistry and check for both to be consdered for $Automate.Installed
                     It was found that the Automate Uninstaller EXE is leaving behind the LabTech registry keys and it was not being detected properly.
                     If the LTSVC Folder or Registry keys are found after the uninstaller runs, the script now performs a manual gutting via PowerShell.
    
    Version        : 1.2
    Date           : 02/17/2020
    Changes        : Add MSIEXEC Log Files to C:\Windows\Temp\Automate_Agent_(Date).log
    Version        : 1.3
    Date           : 05/26/2020
    Changes        : Look for and replace "Enter the server address here" with the actual Automate Server address. 
    Version        : 1.4
    Date           : 06/29/2020
    Changes        : Added Token Parameter for Deployment 
    
.EXAMPLE
    Install-Automate -Server 'automate.domain.com' -LocationID 42 -Token adb68881994ed93960346478303476f4
    This will install the LabTech agent using the provided Server URL, and LocationID.
#>
[CmdletBinding(SupportsShouldProcess=$True)]
    Param(
        [Parameter(ValueFromPipelineByPropertyName = $True, Position=0)]
        [Alias("FQDN","Srv")]
        [string[]]$Server = $Null,
        [Parameter(ValueFromPipelineByPropertyName = $True, Position=1)]
        [AllowNull()]
        [Alias('LID','Location')]
        [int]$LocationID = '1',
        [Parameter(ValueFromPipelineByPropertyName = $True, Position=2)]
        [Alias("InstallerToken")]
        [string[]]$Token = $Null,
        [switch]$Force,
        [Parameter()]
        [AllowNull()]
        [switch]$Show = $False,
        [switch]$Silent,
        [Parameter()]
        [AllowNull()]
        [switch]$Transcript = $False
    )
    $ErrorActionPreference = 'SilentlyContinue'
    $Verbose = If ($PSBoundParameters.Verbose -eq $True) { $True } Else { $False }
    $Error.Clear()
    If ($Transcript) {Start-Transcript -Path "$($env:windir)\Temp\Automate_Deploy.txt" -Force}
    $SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol
    $SoftwarePath = "C:\Support\Automate"
    $Filename = "Automate_Agent.msi"
    $SoftwareFullPath = "$SoftwarePath\$Filename"
    $AutomateURL = "https://$($Server)"
    
    Write-Verbose "Checking Operating System (WinXP and Older)"
    If ([int]((Get-WmiObject Win32_OperatingSystem).BuildNumber) -lt 6000) {
        $OS = ((Get-WmiObject Win32_OperatingSystem).Caption)
        Write-Host "This computer is running $($OS), and is no longer officially supported by ConnectWise Automate" -ForegroundColor Red
        Write-Host "https://docs.connectwise.com/ConnectWise_Automate/ConnectWise_Automate_Supportability_Statements/Supportability_Statement:_Windows_XP_and_Server_2003_End_of_Life" -ForegroundColor Red
        Write-Host ""
        $AutomateURL = "https://$($Server)"
    }
    
    Try {
        Write-Verbose "Enabling downloads to use SSL/TLS v1.2"
        [Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072)
    }
    Catch {
        Write-Verbose "Failed to enable SSL/TLS v1.2"
        Write-Host "This computer is not configured for SSL/TLS v1.2" -ForegroundColor Red
        Write-Host "https://docs.connectwise.com/ConnectWise_Automate/ConnectWise_Automate_Supportability_Statements/Supportability_Statement:_TLS_1.0_and_1.1_Protocols_Unsupported" -ForegroundColor Red
        Write-Host ""
        $AutomateURL = "https://$($Server)"
    }
    
    Try {
        $AutomateURLTest = "$($AutomateURL)/LabTech/"
        $TestURL = (New-Object Net.WebClient).DownloadString($AutomateURLTest)
        Write-Verbose "$AutomateURL is Active"
    }
    Catch {
        Write-Verbose "Could not download from $($AutomateURL). Switching to http://$($Server)"
        $AutomateURL = "http://$($Server)"
    }
    
    $DownloadPath = $null
    If ($Token -ne $null) {
        $DownloadPath = "$($AutomateURL)/Labtech/Deployment.aspx?InstallerToken=$Token"
        Write-Verbose "Downloading from: $($DownloadPath)"
    }
    else {
        Write-Verbose "A -Token <String[]> was not entered"
        $DownloadPath = "$($AutomateURL)/Labtech/Deployment.aspx?Probe=1&installType=msi&MSILocations=$($LocationID)"
        Write-Verbose "Downloading from (Old): $($DownloadPath)"
    }   
        
    Confirm-Automate -Silent -Verbose:$Verbose
    Write-Verbose "If ServerAddress matches, the Automate Agent is currently Online, and Not forced to Rip & Replace then Automate is already installed."
    Write-Verbose (($Global:Automate.ServerAddress -like "*$($Server)*") -and ($Global:Automate.Online) -and !($Force))
    If (($Global:Automate.ServerAddress -like "*$($Server)*") -and $Global:Automate.Online -and !$Force) {
        If (!$Silent) {
            If ($Show) {
              $Global:Automate
            } Else {
              Write-Host "The Automate Agent is already installed on $($Global:Automate.Computername) ($($Global:Automate.ComputerID)) and checked-in $($Global:Automate.LastStatus) seconds ago to $($Global:Automate.ServerAddress)" -ForegroundColor Green
            }
        }
    } Else {
        If (!$Silent -and $Global:Automate.Online -and (!($Global:Automate.ServerAddress -like "*$($Server)*"))) {
            Write-Host "The Existing Automate Server Does Not Match The Target Automate Server." -ForegroundColor Red
            Write-Host "Current Automate Server: $($Global:Automate.ServerAddress)" -ForegroundColor Red
            Write-Host "New Automate Server:     $($AutomateURL)" -ForegroundColor Green
        } # If Different Server 
        Write-Verbose "Downloading Automate Agent from $($AutomateURL)"
            If (!(Test-Path $SoftwarePath)) {md $SoftwarePath | Out-Null}
            Set-Location $SoftwarePath
            If ((test-path $SoftwareFullPath)) {Remove-Item $SoftwareFullPath | Out-Null}
            Try {
                Write-Verbose "Downloading from: $($DownloadPath)"
                Write-Verbose "Downloading to:   $($SoftwareFullPath)"
                $WebClient = New-Object System.Net.WebClient
                $WebClient.DownloadFile($DownloadPath, $SoftwareFullPath)
                Write-Verbose "Download Complete"
            }
            Catch {
                Write-Host "The Automate Server was inaccessible or the Token Parameters were not entered or valid. Failed to Download:" -ForegroundColor Red
                Write-Host $DownloadPath -ForegroundColor Red
                Write-Host "Help: Get-Help Install-Automate -Full"
                Write-Host "Exiting Installation..."    
                Break                
            }
            
            Write-Verbose "Removing Existing Automate Agent"
            Uninstall-Automate -Force:$Force -Silent:$Silent -Verbose:$Verbose
            If (!$Silent) {Write-Host "Installing Automate Agent to $AutomateURL"}
            Stop-Process -Name "ltsvcmon","lttray","ltsvc","ltclient" -Force -PassThru
            $Date = (get-date -UFormat %Y-%m-%d_%H-%M-%S)
            $LogFullPath = "$env:windir\Temp\Automate_Agent_$Date.log"
            $InstallExitCode = (Start-Process "msiexec.exe" -ArgumentList "/i $($SoftwareFullPath) /quiet /norestart LOCATION=$($LocationID) SERVERADDRESS=$($AutomateURL) /L*V $($LogFullPath)" -NoNewWindow -Wait -PassThru).ExitCode
            Write-Verbose "MSIEXEC Log Files: $LogFullPath"
            If ($InstallExitCode -eq 0) {
                If (!$Silent) {Write-Verbose "The Automate Agent Installer Executed Without Errors"}
            } Else {
                Write-Host "Automate Installer Exit Code: $InstallExitCode" -ForegroundColor Red
                Write-Host "Automate Installer Logs: $LogFullPath" -ForegroundColor Red
                Write-Host "The Automate MSI failed. Waiting 15 Seconds..." -ForegroundColor Red
                Start-Sleep -s 15
                Write-Host "Installer will execute twice (KI 12002617)" -ForegroundColor Yellow
                $Date = (get-date -UFormat %Y-%m-%d_%H-%M-%S)
                $LogFullPath = "$env:windir\Temp\Automate_Agent_$Date.log"
                $InstallExitCode = (Start-Process "msiexec.exe" -ArgumentList "/i $($SoftwareFullPath) /quiet /norestart LOCATION=$($LocationID) SERVERADDRESS=$($AutomateURL) /L*V $($LogFullPath)" -NoNewWindow -Wait -PassThru).ExitCode
                Write-Host "Automate Installer Exit Code: $InstallExitCode" -ForegroundColor Yellow
                Write-Host "Automate Installer Logs: $LogFullPath" -ForegroundColor Yellow
            }# End Else
        If ($InstallExitCode -eq 0) {
            While ($Counter -ne 30) {
                $Counter++
                Start-Sleep 10
                Confirm-Automate -Silent -Verbose:$Verbose
                If ($Global:Automate.Server -like "Enter the server address here*") {
                    Write-Verbose "The Automate Server Address was not written properly"
                    Write-Verbose "Manually overwriting the Server Address to: $($AutomateURL)"
                    Set-ItemProperty -Path HKLM:\SOFTWARE\LabTech\Service 'Server Address' -Value $AutomateURL –Force
                    Write-Verbose "Restarting LTService after correcting the Server Address"
                    Get-Service LTService | Where {$_.Status -eq "Running"} | Restart-Service -Force
                    Confirm-Automate -Silent -Verbose:$Verbose
                }
                If ($Global:Automate.Online -and $Global:Automate.ComputerID -ne $Null) {
                    If (!$Silent) {
                        Write-Host "The Automate Agent Has Been Successfully Installed" -ForegroundColor Green
                        $Global:Automate
                    }#end If Silent
                    Break
                } # end If
            }# end While
        } Else {
            While ($Counter -ne 3) {
                $Counter++
                Start-Sleep 10
                Confirm-Automate -Silent -Verbose:$Verbose
                If ($Global:Automate.Server -like "Enter the server address here*") {
                    Write-Verbose "The Automate Server Address was not written properly"
                    Write-Verbose "Manually overwriting the Server Address to: $($AutomateURL)"
                    Set-ItemProperty -Path HKLM:\SOFTWARE\LabTech\Service 'Server Address' -Value $AutomateURL –Force
                    Write-Verbose "Restarting LTService after correcting the Server Address"
                    Get-Service LTService | Where {$_.Status -eq "Running"} | Restart-Service -Force
                    Confirm-Automate -Silent -Verbose:$Verbose
                }
                If ($Global:Automate.Online -and $Global:Automate.ComputerID -ne $Null) {
                    If (!$Silent) {
                        Write-Host "The Automate Agent Has Been Successfully Installed" -ForegroundColor Green
                        $Global:Automate
                    }#end If Silent
                    Break
                } # end If
            } # end While
        } # end If ExitCode 0
        Confirm-Automate -Silent -Verbose:$Verbose
        If (!($Global:Automate.Online -and $Global:Automate.ComputerID -ne $Null)) {
            If (!$Silent) {
                    Write-Host "The Automate Agent FAILED to Install" -ForegroundColor Red
                    $Global:Automate
            }# end If Silent
        } # end If Not Online
    } # End 
    If ($Transcript) {Stop-Transcript}
} #End Function Install-Automate
########################
Set-Alias -Name LTI -Value Install-Automate -Description 'Install Automate Agent'
########################










#https://superuser.com/questions/1068382/how-to-remove-all-the-tiles-in-the-windows-10-start-menu
#Unpins all tiles from the Start Menu
    Write-Host "Unpinning all tiles from the start menu"
    (New-Object -Com Shell.Application).
    NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').
    Items() |
    %{ $_.Verbs() } |
    ?{$_.Name -match 'Un.*pin from Start'} |
    %{$_.DoIt()}









 New-PSDrive  HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
    $Keys = @(
            
        #Remove Background Tasks
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
            
        #Windows File
        "HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            
        #Registry keys to delete if they aren't uninstalled by RemoveAppXPackage/RemoveAppXProvisionedPackage
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
            
        #Scheduled Tasks to delete
        "HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
            
        #Windows Protocol Keys
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
               
        #Windows Share Target
        "HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
    )
        
    #Removes the keys listed above.
    Write-Host "Removing Bloatware Keys from registry"
    ForEach ($Key in $Keys) {
        Remove-Item $Key -Recurse
    }










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