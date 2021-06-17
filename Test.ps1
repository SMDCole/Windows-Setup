function Return-Confirm {
 $script:Choice = $Confirm.Text.ToString()
 $Form.Close()
}

function ConfirmForm{
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")


    $Form = New-Object System.Windows.Forms.Form

    $Form.width = 300
    $Form.height = 225
    $Form.Text = ”Confirm Form”

    #$Confirm = new-object System.Windows.Forms.TextBox
    #$Confirm.Location = new-object System.Drawing.Size(100,10)
    #$Confirm.Size = new-object System.Drawing.Size(170,30)

    $Form.Controls.Add($Confirm)

    $ConfirmLabel = new-object System.Windows.Forms.Label
    $ConfirmLabel.Location = new-object System.Drawing.Size(90,10) 
    $ConfirmLabel.size = new-object System.Drawing.Size(100,40) 
    $ConfirmLabel.Text = "Computer name is: $ComputerName"
    $Form.Controls.Add($ConfirmLabel)

    $ConfirmLabel2 = new-object System.Windows.Forms.Label
    $ConfirmLabel2.Location = new-object System.Drawing.Size(90,60) 
    $ConfirmLabel2.size = new-object System.Drawing.Size(100,40) 
    $ConfirmLabel2.Text = "Administrator username is: $AdminName"
    $Form.Controls.Add($ConfirmLabel2)

    $ConfirmLabel3 = new-object System.Windows.Forms.Label
    $ConfirmLabel3.Location = new-object System.Drawing.Size(90,110) 
    $ConfirmLabel3.size = new-object System.Drawing.Size(100,40) 
    $ConfirmLabel3.Text = "Is this correct?"
    $Form.Controls.Add($ConfirmLabel3)

    $Button = new-object System.Windows.Forms.Button
    $Button.Location = new-object System.Drawing.Size(50,150)
    $Button.Size = new-object System.Drawing.Size(100,20)
    $Button.Text = "Yes"
    $Button.Add_Click({Return-Confirm})
    $form.Controls.Add($Button)

    $Button = new-object System.Windows.Forms.Button
    $Button.Location = new-object System.Drawing.Size(150,150)
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