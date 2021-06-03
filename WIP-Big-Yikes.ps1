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
        [int]$LocationID,
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
    

    ############################################
    #Use a csv to select a location that corresponds
    #To a location ID to pass into $LocationID
    #To install automate
    $CSV = Import-Csv C:\Users\cole\Documents\Clients.csv

    [array]$DropDownArray = $CSV.Client

    # This Function Returns the Selected Value and Closes the Form

    function Return-DropDown {
        $script:Choice = $DropDown.SelectedItem.ToString()
        $Form.Close()
    }

    function selectShare{
        [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
        [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")


        $Form = New-Object System.Windows.Forms.Form

        $Form.width = 300
        $Form.height = 150
        $Form.Text = ”Select Client”

        $DropDown = new-object System.Windows.Forms.ComboBox
        $DropDown.Location = new-object System.Drawing.Size(100,10)
        $DropDown.Size = new-object System.Drawing.Size(170,30)

        ForEach ($Item in $DropDownArray) {
         [void] $DropDown.Items.Add($Item)
        }

        $Form.Controls.Add($DropDown)

        $DropDownLabel = new-object System.Windows.Forms.Label
        $DropDownLabel.Location = new-object System.Drawing.Size(10,10) 
        $DropDownLabel.size = new-object System.Drawing.Size(100,40) 
        $DropDownLabel.Text = "Select a client"
        $Form.Controls.Add($DropDownLabel)

        $Button = new-object System.Windows.Forms.Button
        $Button.Location = new-object System.Drawing.Size(100,50)
        $Button.Size = new-object System.Drawing.Size(100,20)
        $Button.Text = "Select"
        $Button.Add_Click({Return-DropDown})
        $form.Controls.Add($Button)

        $Form.Add_Shown({$Form.Activate()})
        [void] $Form.ShowDialog()


        return $script:choice
    }
    $LocationID = selectShare

    ############################################

    $ErrorActionPreference = 'SilentlyContinue'
    $Verbose = If ($PSBoundParameters.Verbose -eq $True) { $True } Else { $False }
    $Error.Clear()
    If ($Transcript) {Start-Transcript -Path "$($env:windir)\Temp\Automate_Deploy.txt" -Force}
    $SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol
    $SoftwarePath = "C:\Support\Automate"
    $Filename = "Automate_Agent.msi"
    $SoftwareFullPath = "$SoftwarePath\$Filename"
    $AutomateURL = "https://$($Server)"
    
    #Checking OS Version
    Write-Verbose "Checking Operating System (WinXP and Older)"
    If ([int]((Get-WmiObject Win32_OperatingSystem).BuildNumber) -lt 6000) {
        $OS = ((Get-WmiObject Win32_OperatingSystem).Caption)
        Write-Host "This computer is running $($OS), and is no longer officially supported by ConnectWise Automate" -ForegroundColor Red
        Write-Host "https://docs.connectwise.com/ConnectWise_Automate/ConnectWise_Automate_Supportability_Statements/Supportability_Statement:_Windows_XP_and_Server_2003_End_of_Life" -ForegroundColor Red
        Write-Host ""
        $AutomateURL = "https://$($Server)"
    }
    
    #Enbales SSL/TLS Downloads
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
    
    #Tests URL Download of agent
    Try {
        $AutomateURLTest = "$($AutomateURL)/LabTech/"
        $TestURL = (New-Object Net.WebClient).DownloadString($AutomateURLTest)
        Write-Verbose "$AutomateURL is Active"
    }
    Catch {
        Write-Verbose "Could not download from $($AutomateURL). Switching to http://$($Server)"
        $AutomateURL = "http://$($Server)"
    }
    
    #Tries token download if URL Fails
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
    
    #Checks for Automate already being installed    
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
            
            #If forced, Automate will uninstall and reinstall
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