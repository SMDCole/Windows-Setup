# This Function Returns the Selected Value and Closes the Form

function Return-CompName {
 $script:Choice = $CompName.Text.ToString()
 $Form.Close()
}

function selectCompName{
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")


    $Form = New-Object System.Windows.Forms.Form

    $Form.width = 300
    $Form.height = 150
    $Form.Text = ”Computer Name”

    $CompName = new-object System.Windows.Forms.TextBox
    $CompName.Location = new-object System.Drawing.Size(100,10)
    $CompName.Size = new-object System.Drawing.Size(170,30)

    $Form.Controls.Add($CompName)

    $CompNameLabel = new-object System.Windows.Forms.Label
    $CompNameLabel.Location = new-object System.Drawing.Size(10,10) 
    $CompNameLabel.size = new-object System.Drawing.Size(100,40) 
    $CompNameLabel.Text = "Enter a computer name"
    $Form.Controls.Add($CompNameLabel)

    $Button = new-object System.Windows.Forms.Button
    $Button.Location = new-object System.Drawing.Size(100,50)
    $Button.Size = new-object System.Drawing.Size(100,20)
    $Button.Text = "Select"
    $Button.Add_Click({Return-CompName})
    $form.Controls.Add($Button)

    $Form.Add_Shown({$Form.Activate()})
    [void] $Form.ShowDialog()


    return $script:choice
}

$Computername = selectCompName
write-host $Computername

##############################################################################################################

function Return-AdminName {
 $script:Choice = $AdminName.Text.ToString()
 $Form.Close()
}

function selectAdminName{
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")


    $Form = New-Object System.Windows.Forms.Form

    $Form.width = 300
    $Form.height = 150
    $Form.Text = ”Admin Name”

    $AdminName = new-object System.Windows.Forms.TextBox
    $AdminName.Location = new-object System.Drawing.Size(100,10)
    $AdminName.Size = new-object System.Drawing.Size(170,30)

    $Form.Controls.Add($AdminName)

    $AdminNameLabel = new-object System.Windows.Forms.Label
    $AdminNameLabel.Location = new-object System.Drawing.Size(10,10) 
    $AdminNameLabel.size = new-object System.Drawing.Size(100,40) 
    $AdminNameLabel.Text = "Enter an administrator username"
    $Form.Controls.Add($AdminNameLabel)

    $Button = new-object System.Windows.Forms.Button
    $Button.Location = new-object System.Drawing.Size(100,50)
    $Button.Size = new-object System.Drawing.Size(100,20)
    $Button.Text = "Select"
    $Button.Add_Click({Return-AdminName})
    $form.Controls.Add($Button)

    $Form.Add_Shown({$Form.Activate()})
    [void] $Form.ShowDialog()


    return $script:choice
}

$AdminName = selectAdminName
write-host $AdminName

##############################################################################################################

function Return-Confirm {
 $script:Choice = $Confirm.Text.ToString()
 $Form.Close()
}

function ConfirmForm{
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")


    $Form = New-Object System.Windows.Forms.Form

    $Form.width = 450
    $Form.height = 150
    $Form.Text = ”Confirm Form”

    #$Confirm = new-object System.Windows.Forms.TextBox
    #$Confirm.Location = new-object System.Drawing.Size(100,10)
    #$Confirm.Size = new-object System.Drawing.Size(170,30)

    $Form.Controls.Add($Confirm)

    $ConfirmLabel = new-object System.Windows.Forms.Label
    $ConfirmLabel.Location = new-object System.Drawing.Size(10,10) 
    $ConfirmLabel.size = new-object System.Drawing.Size(100,40) 
    $ConfirmLabel.Text = "Computer name is: $ComputerName"
    $Form.Controls.Add($ConfirmLabel)

    $ConfirmLabel2 = new-object System.Windows.Forms.Label
    $ConfirmLabel2.Location = new-object System.Drawing.Size(10,60) 
    $ConfirmLabel2.size = new-object System.Drawing.Size(100,40) 
    $ConfirmLabel2.Text = "Administrator username is: $AdminName"
    $Form.Controls.Add($ConfirmLabel2)

    $ConfirmLabel3 = new-object System.Windows.Forms.Label
    $ConfirmLabel3.Location = new-object System.Drawing.Size(10,110) 
    $ConfirmLabel3.size = new-object System.Drawing.Size(100,40) 
    $ConfirmLabel3.Text = "Is this correct?"
    $Form.Controls.Add($ConfirmLabel3)

    $Button = new-object System.Windows.Forms.Button
    $Button.Location = new-object System.Drawing.Size(100,100)
    $Button.Size = new-object System.Drawing.Size(100,20)
    $Button.Text = "Yes"
    $Button.Add_Click({Return-Confirm})
    $form.Controls.Add($Button)

    $Button = new-object System.Windows.Forms.Button
    $Button.Location = new-object System.Drawing.Size(200,100)
    $Button.Size = new-object System.Drawing.Size(100,20)
    $Button.Text = "No"
    $Button.Add_Click({Return-Confirm})
    $form.Controls.Add($Button)

    $Form.Add_Shown({$Form.Activate()})
    [void] $Form.ShowDialog()


    return $script:choice
}

$Confirm = ConfirmForm
write-host $Confirm




Write-Output "`n`nComputer Name: $ComputerName `nAdmin username: $AdminName`n Confirm value: $Confirm`n"
$confirmInfo = (Read-Host "Is this information correct? Y/N")