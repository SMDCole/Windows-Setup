$CSV = Import-Csv C:\Users\cole\Documents\Clients.csv

# These are the starting folders
$documentRoots = $CSV.Client


# Load Windows forms assemblies
[void][Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
[void][Reflection.Assembly]::LoadWithPartialName("System.Drawing")


#
# documentsToolStripMenuItem - this is the bit which says "Documents" along the top
#
$documentsToolStripMenuItem = new-object System.Windows.Forms.ToolStripMenuItem
$documentsToolStripMenuItem.Name = "documentsToolStripMenuItem"
$documentsToolStripMenuItem.Text = "&Documents"


#
# documents helper function, this generates submenus on-the-fly.
#
$Child = $CSV.subclient
function Add-SubMenuItems {
    
    # Only make each submenu once.
    # If you move the mouse away and back we don't want to recreate it.
    if ($this.DropDownItems.Count -eq 1 -and $this.DropDownItems[0].Text -eq '')
    {
        $this.DropDownItems.Clear()    # Remove placeholder
        
        # Add new menu items for each file or directory.
        #  - directories fill in their contents into their submenu when hovered over.
        #  - files print their name when clicked.
        [array]$items = $Child #-LiteralPath $this.Tag -ErrorAction SilentlyContinue | 
                            #Sort-Object -Property PSIsContainer, Name

        if ($items.Count -gt 0)
        {
            $items | ForEach-Object {

                $tempItem = New-Object System.Windows.Forms.ToolStripMenuItem -ArgumentList $_.Name
                $tempItem.Tag = $_.FullName
                
                if ($_.PsIsContainer)  # Directory - add a blank submenu item, so it has the > hint
                {
                    $tempItem.Add_MouseHover({ Add-SubMenuItems })
                    $tempSubSubMenu = New-Object System.Windows.Forms.ToolStripMenuItem  
                    [void]$tempItem.DropdownItems.Add($tempSubSubMenu)
                }
                else  # it's a file, add a Click handler
                {
                   $tempItem.Add_Click({ 
                       Write-Host -ForegroundColor Magenta "$($this.Tag)"
                    })
                }
                
                # add each new item to the menu
                [void]$this.DropDownItems.Add($tempItem)
            }
        }
        else
        {
            $this.Text = $this.Text + '  (empty)'
        }
    }
}

# For each document root,
# Create a menu entry to go under "Documents".
# Give it an empty sub menu, so it has the > arrow.
# Register an event handler so it responds to mouse hover.
# Add it to the document parent menu.
#
# This can't use the helper function because it
# adds to the Documents top-level menu.
foreach ($root in $documentRoots)
{
    $tempItem = New-Object System.Windows.Forms.ToolStripMenuItem -ArgumentList ($root)
    $tempItem.Add_MouseHover({ Add-SubMenuItems })
    $tempItem.Tag = $root
    $tempSubMenu = New-Object System.Windows.Forms.ToolStripMenuItem
    [void]$tempItem.DropDownItems.Add($tempSubMenu)
    
    [void]$documentsToolStripMenuItem.DropDownItems.Add($tempItem)
}

#
# Main menu bar
#
$MenuStrip = new-object System.Windows.Forms.MenuStrip
[void]$MenuStrip.Items.Add($documentsToolStripMenuItem)
$MenuStrip.Location = new-object System.Drawing.Point(0, 0)
$MenuStrip.Name = "MenuStrip"
$MenuStrip.Size = new-object System.Drawing.Size(354, 24)
$MenuStrip.TabIndex = 0
$MenuStrip.Text = "menuStrip1"


#
# Main Form
#
$MenuForm = new-object System.Windows.Forms.form
$MenuForm.ClientSize = new-object System.Drawing.Size(354, 141)
[void]$MenuForm.Controls.Add($MenuStrip)
$MenuForm.MainMenuStrip = $MenuStrip
$MenuForm.Name = "MenuForm"
$MenuForm.Text = "I've got a menu"
function OnFormClosing_MenuForm($Sender,$e){ 
    # $this represent sender (object)
    # $_ represent  e (eventarg)

    # Allow closing
    ($_).Cancel= $False
}
$MenuForm.Add_FormClosing( { OnFormClosing_MenuForm $MenuForm $EventArgs} )
$MenuForm.Add_Shown({$MenuForm.Activate()})
$MenuForm.ShowDialog()
#Free ressources
$MenuForm.Dispose()