$CSV = Import-Csv C:\Users\cole\Documents\Clients.csv

[array]$DropDownArray = $CSV.Client
[array]$DropDownRef = $CSV.'LocationID'

# This Function Returns the Selected Value and Closes the Form

function Return-DropDown {
 $script:Choice = $DropDown.SelectedItem.ToString()
 $Form.Close()
}

function selectClient{
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

$client = selectClient
write-host $client