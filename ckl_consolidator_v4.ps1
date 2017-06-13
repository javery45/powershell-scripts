# Author:   Justin Avery
# Date:     03/29/2017
# Purpose:  Script consolidates finding statuses, finding details, and comments from older versions of STIG checklists into newer versions of STIG checklists. Any new VulnIDs in the new checklists are left untouched and would still need to
#           be reviewed manually by a person. Script will present two pop-up dialog windows asking user to select each of the two checklist files to be consolidated, and then will consolidate them.

$global:count = 0
$date = Get-Date -Format MMddyyyy
$time = Get-Date -Format hhmm
$current_dir = split-path -parent $MyInvocation.MyCommand.Definition

# declare function that controls the pop-up windows used to select the older and newer checklist files to consolidate.
Function Select-FileDialog
{
    param([string]$Description="Select Folder",[string]$RootFolder="Desktop")

 [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null     

    $objForm = New-Object System.Windows.Forms.OpenFileDialog
    $objForm.filter = "CKL (*.ckl)| *.ckl"
        IF($count -eq 0)
        {
        $objForm.Title = "Choose the older checklist file"
        }
        ELSE
        {
        $objForm.Title = "Choose the newer/delta checklist file"
        }
        $global:count += 1
        $Show = $objForm.ShowDialog()
        If ($Show -eq "OK")
        {
            Return $objForm.FileName
        }
        ELSE
        {
            $cancelPopup = New-Object -ComObject Wscript.Shell
            $cancelPopup.Popup("Checklist consolidator has been cancelled",0,"CKL Consolidator Cancelled",0x0)
            Exit

        }
        Else
        {
            Write-Error "Operation cancelled by user."
           
        }
}
    
    $file1 = Select-FileDialog
    $file2 = Select-FileDialog
    
$separated = $file2.split("\,.")
$root_delta_filename = $separated[($separated.count)-2]

$low1 = $file1.ToLower()
$low2 = $file2.ToLower()

# verify that the two files selected are both .ckl file extensions
IF($low1.EndsWith(".ckl") -eq $False)
{
    Write-Host "The first file selected was not a .ckl file format. Exiting script..."
    Exit
}
ELSE
{
    #Keep going...
}

IF($low2.EndsWith(".ckl") -eq $False)
{
    Write-Host "The second file selected was not a .ckl file format. Exiting script..."
    Exit
}
ELSE
{
    #Keep going...
}
 

#import the two checklist files to be merged: original checklist and delta checklist
$og_ckl_path = $file1
$delta_ckl_path = $file2



# create xml objects
$og_ckl = new-object -TypeName XML
$delta_ckl = new-object -TypeName XML

# load the xml data from ckl files into those xml objects
$og_ckl.load($og_ckl_path)
$delta_ckl.load($delta_ckl_path)

# preserve the way XML whitespace is formatted in the existing ckls
$og_ckl.PreserveWhitespace = $true
$delta_ckl.PreserveWhitespace = $true

# create array to hold list of VulnIDs from delta ckl
$delta_ckl_vulnids = @()

#get delta checklist filename
$delta_ckl.checklist.stigs.istig.stig_info.si_data[5].sid_data

# populate list of all VulnIDs that are in delta ckl by parsing through them all
  foreach($item in $delta_ckl.checklist.stigs.istig.vuln)
 {
       write-host "Getting list of delta ckl VulnIDs"
       $delta_ckl_vulnids += $item.stig_data[0].attribute_data
 
 }
 
 #start iterating through each item in the original ckl
   foreach($og_item in $og_ckl.checklist.stigs.istig.vuln)
 {
       $og_ckl_vulnid = $og_item.stig_data[0].attribute_data
       
       #see if the vulnID from the original ckl is also in the delta ckl
       IF($delta_ckl_vulnids -contains $og_ckl_vulnid)
       {
        write-host "Found VulnID in delta ckl that matches original ckl"
       
        #if it is, start iterating through the xml of the delta ckl to find that particular xml node
           foreach($delta_item in $delta_ckl.checklist.stigs.istig.vuln)
            {
                
                IF($delta_item.stig_data[0].attribute_data -eq $og_ckl_vulnid)
                {
                    write-host "Found matching vulnid branch..."
                    # at this point, it's found the matching VulnID in the delta ckl. Start doing work, son!
                    
                    IF($delta_item.status -ne "Not_Reviewed")
                    {
                        # a vuln item in the delta ckl matched the original ckl, but the delta item has been altered, so data for this item will NOT be copied over from the original ckl. If an item in a delta ckl has been altered, it is probably more up to date.
                        BREAK
                    }
                    
                    IF($delta_item.finding_details -ne "")
                    {
                        # a vuln item in the delta ckl matched the original ckl, but the delta item has been altered, so data for this item will NOT be copied over from the original ckl.
                        BREAK
                    }
                    
                    IF($delta_item.comments -ne "")
                    {
                        # a vuln item in the delta ckl matched the original ckl, but the delta item has been altered, so data for this item will NOT be copied over from the original ckl.
                        BREAK
                    }
                    
                    write-host "attempting to copy status"
                    # copy STATUS
                    $delta_item.status = $og_item.status
                    
                    write-host "attempting to copy finding details"
                    # copy FINDING DETAILS (if it's not null)
                    $delta_item.finding_details = $og_item.finding_details
                    
                    write-host "attempting to copy comments"
                    # copy FINDING COMMENTS (if it's not null)
                    $delta_item.comments = $og_item.comments
                    
                }
            }
       
        }
 
 }

# save the delta checklist as a new file
write-host " "
write-host " " 
write-host "attempting to save new consolidated ckl"

$new_filename = $root_delta_filename+"_"+$time+"_"+$date+".ckl"
$new_path = $current_dir +"\"+$new_filename
$delta_ckl.save($new_path)

# display pop up window to inform user script has completed
$wshell = New-Object -ComObject Wscript.Shell


$wshell.Popup("Checklist consolidator has finished.`n`nConsolidated checklist saved to $new_path `n`n Please open this consolidated checklist file in the DISA STIG Viewer, and re-save it as another file. Doing so will clean up the underlying XML syntax of the file.",0,"CKL Consolidator Complete",0x1)

