############################################################################################################################# 
##                                                                                                                         ## 
##  Author: Peter Thung "the Man"                                                                                                ## 
##                                                                                                                         ## 
##  Version:  1.0                                                                                                          ## 
##                                                                                                                         ## 
##  Date:  03/29/2012                                                                                                      ## 
##                                                                                                                         ## 
##  Purpose: Revised combination of the 3 individual scripts to locate and remove inactive accounts from AD. 
## 12/3/2013
##  -Peter Thung modified dormant Account detection code to leverage 
##        http://dmitrysotnikov.wordpress.com/2008/07/18/finding-the-latest-logon-time/
##   which searches all domain controllers for LastLogon as well a being sensitive to 
##   accounts that were created, but no user has been logged in.
## - Add a $global:HashOfProblemAccounts bucket to keep track of accounts that go over the retry
## - threshold to determine LastLogon to eliminate false positives. As well as removing them from 
##   dormant account list. 
## 1/13/2014
##  - made script be able to enumerate multiple domains using -service flag on QAD-User
## 1/15/2013
##  - Made some configuration variable changes.
## 1/17/2013 - v3
##  - Fixed disabled user feature. Issue when account to be disabled was CLO'd.
## 10/15/15
##	- Justin Avery, changed variable $inactiveUserCSVFileName to include the date and time in the filename path. This should 
##	prevent previous issues where the script would run but email the same list with the same account names each day, whereas 
##	it should show a list of different account names each day that were disabled when the script was ran.
##  
############################################################################################################################# 
#add-pssnapin quest*  #-EA SilentlyContinue                                                                                                    
#This code snippit gets rid of the error when trying to load snappin if it is already loaded
$requiredSnapin = "quest*"
if( (Get-PSSnapin -Name $requiredSnapin -Debug -ErrorAction SilentlyContinue) -eq $null)
{
	Add-PSSnapin $requiredSnapin
}


#Region Configuration
$thedate = (Get-Date -Format MM-dd-yyyy).ToString()
$thetime = (Get-Date -Format HHmm).ToString()
$fully_qualified_Domain = "sscpac.srdte.spawar.navy.smil.mil"
#$fully_qualified_Domain = "srdte.spawar.navy.smil.mil"
$fully_qualified_Domain_split = $fully_qualified_Domain.Split('.')  # Do not Touch
$first_part_fully_qualifed_domain = $fully_qualified_Domain_split[0].ToUpper()  # e.g. SSCPAC
$filterOutDisabledAccountsInDetection = $false  # $false means show disabled dormant accounts instead of just enabled accounts.

$serviceValue = $fully_qualified_Domain
$OU = "$serviceValue/"
#$OU = "srdte.spawar.navy.mil/Users" 
$NotLoggedOnFor = 335
$resultsDirectory = "C:\scripts\Dormant\results";
$inactiveUserCSVFileName= "inactive_users.$first_part_fully_qualifed_domain" + $thedate + "_" + $thetime + ".csv"
$allUserCSVFileName= "all_users.$first_part_fully_qualifed_domain.csv"
$auditAllUserCSVFileName= "audit_all_users.$first_part_fully_qualifed_domain.csv"
$potentialDormantUsersNeedingRescan = "potentialDormant_users_requiring_rescan_$first_part_fully_qualifed_domain.csv"
$debugFlag = $true
$auditFlag = $true  # Creates an audit file that shows the individaul LogonTimes across all DCs
#$runInteractive = $false # Will
$runInteractive = $true # Will enable a menu to allow scanning for dormant accounts, disabling them.
$global:smtpServer = "smtp.spawar.navy.smil.mil"
$global:sendEmail = $true
$get_adUser_retry_Attempts = 2
### Email Configuration
# $emailFromParam, $emailToParam, $emailCCParam, $emailSubjectParam, $emailBodyParam, $pathToEmailAttachment)
$emailFrom = "swan_windows_admins@spawar.navy.smil.mil"  
$emailTo = "javery@spawar.navy.smil.mil"
$emailCC = "swan_windows_admins@spawar.navy.smil.mil"
$emailSubject = "Domain:$first_part_fully_qualifed_domain Dormant Detection Tool Results"
$emailBody = "Dormant Threshold (Either Last Logged On or When Created): $NotLoggedOnFor`r`n"
$pathToEmailAttachment = $resultsDirectory + "\" + $inactiveUserCSVFileName
$pathToEmailAttachmentAuditAllUsers = $resultsDirectory + "\" + $auditAllUserCSVFileName
$pathToEmailAttachmentPotentialDormantUsersNeedingRescan = $resultsDirectory + "\" + $potentialDormantUsersNeedingRescan

#EndRegion Configuration

$listOfAttachments=@()
$listOfAttachments += $pathToEmailAttachment;
$listOfAttachments += $pathToEmailAttachmentPotentialDormantUsersNeedingRescan;
if($auditFlag) {
	$listOfAttachments += $pathToEmailAttachmentAuditAllUsers
}
#Region EmailBodyConfiguration
$tempBodyNewLine = "Retry Attempt Amount to retry query for LastLogon/WhenCreated is set to try " +  $get_adUser_retry_Attempts.ToString() + " times.  `r`n"
$emailBody += $tempBodyNewLine
#EndRegion EmailBodyConfiguration

#Region Global Structures 
# Note, this was made global out of laziness becuase of challenge to output to csv file line by line.
$global:ListOfIdentifiedAccountsAudit = @()
$global:HashOfProblemAccounts =@{}
$currentDate = Get-Date
#EndRegion Global Structures

new-item $resultsDirectory -type directory  -EA SilentlyContinue 
$inactiveUserCSVFileAbsolutePath = $resultsDirectory + "\" + $inactiveUserCSVFileName
$allUserCSVFileAbsolutePath = $resultsDirectory + "\" + $allUserCSVFileName
$auditAllUserCSVFileAbsolutePath = $resultsDirectory + "\" + $auditAllUserCSVFileName
new-item $resultsDirectory -type directory  -EA SilentlyContinue 

# Currently only handles LastLogon and WhenCreated
# Due to errors detected from Get-QADuser occasionally like The server is not operational
# implemented a retry mechanism, that is configurable.It will try again until try is greater than
# $attemptThreshold
# Expects a Date Object back.
function getUserAttributeByName($dcNameParam, $attributeName, $attemptNum, $attemptThreshHold, $userLogonName, $fileToSaveAuditAllusersParam){
	$returnResult = $null
	$errorContent = "OK"
	if($debugFlag) {
		Write-Host "Called: getuserAttributeByName, AttemptNumber: $attemptNum, DcName: $dcNameParam, LognName: $userLogonName,  AttributeName: $attributeName"
	}
	if($attemptNum -gt ($attemptThreshHold + 1)) {
		if($auditFlag) {
		   $properties = @{'samaccountname'=$userLogonName;
				'DomainName'=$dcNameParam;
				'AttemptNum'=$attemptNum;
				'Notes'="Error it retrieving LastLogon value. Threshold[$attemptThreshHold] Reached Check Dormant Account Manually or increase threshold and Rerun or contact Quest";
	            }
	        $object = New-Object –TypeName PSObject –Prop $properties
			$global:ListOfIdentifiedAccountsAudit += $object
		}		
	    if($global:HashOfProblemAccounts -ne $null) {
	   		$global:HashOfProblemAccounts.Add($userLogonName, $object)
		} 
		#else {
		#	$global:HashOfProblemAccounts = @{$userLogonName = $object}
		#}		

	  return $returnResult
	}
	if($attributeName -eq "LastLogon") {
	
	    (Get-QADUser -ErrorVariable LogonNameError -Service $dcNameParam -SamAccountName $userLogonName).LastLogon | Tee-Object -Variable lastLogonIndividual
		if(!$?) { # this is how to detect if there was an error in the Get
		   Write-Error "Error was caught[With dollar sign question mark] and detected from Get-QADUser when query for LastLogon = $lastLogonIndividual, DcName: $dcNameParam, LognName: $userLogonName,  AttributeName: $attributeName "
			if($LogonNameError -ne $null -and $LogonNameError.count -gt 0) {
			 	$errorCount = $LogonNameError.count
				$errorContent = $LogonNameError[0]
			    Write-Error "Count: $errorCount Error content: $errorContent" 
			    Write-Error "Attempt # $attemptNum failed. Trying again"
			  $lastLogonIndividual =  getUserAttributeByName $dcNameParam $attributeName ($attemptNum + 1) $attemptThreshHold $userLogonName
			}
		}
		
		if($debugFlag) {
				Write-Host "Queried Attribute: $attributeName,  AttemptNumber: $attemptNum, DCname = $DCname, userLogonName: " $userLogonName "lastlogon:" $lastLogonIndividual			
		}
		$returnResult = $lastLogonIndividual
	} elseif ($attributeName -eq "WhenCreated") {
	        
				(Get-QADUser -ErrorVariable WhenCreatedError -Verbose -Debug -Service $dcNameParam -SamAccountName $userLogonName).whenCreated | Tee-Object -Variable whenCreatedIndividual
				if(!$?) {
				    Write-Error "Error was caught[With dollar sign question mark] and detected from QADUser when query for WhenCreated value = $whenCreatedIndividual, DcName: $dcNameParam, LognName: $userLogonName,  AttributeName: $attributeName "
				    if($WhenCreatedError -ne $null -and $WhenCreatedError.count -gt 0) {
						$errorCount = $WhenCreatedError.count
						$errorContent = $WhenCreatedError[0]
					    Write-Error "Count: $errorCount Error content: $errorContent" 
					    $whenCreatedIndividual =  getUserAttributeByName $dcNameParam $attributeName ($attemptNum + 1) $attemptThreshHold $userLogonName
					}
				}
				if($debugFlag) {
					Write-Host "Queried Attribute: $attributeName,  AttemptNumber: $attemptNum,  DCname = $dcNameParam, userLogonName: " $userLogonName "WhenCreated:" $whenCreatedIndividual			
		        }
				$returnResult = $whenCreatedIndividual
	}
	
	$numDaysSinceLastLoggedInOrCreated = "N/A"
	if($returnResult -ne $null) {
		if($returnResult.GetType().Name -eq "DateTime") {
	    	$numDaysSinceLastLoggedInOrCreated = ($global:currentDate - $returnResult).Days
		} elseif($returnResult.GetType().Name -eq "Object[]") {  # It appears when getuserAttributeByname returns back from recursive function to itself it adds the DateObject to an array vice replacing the existing DateTimeObject.
			#After Calculation, go ahead and reset it back.
			$numDaysSinceLastLoggedInOrCreated = ($global:currentDate - $returnResult[$returnResult.Count - 1]).Days
			$returnResult = $returnResult[$returnResult.Count - 1]
		}
	} 
    # samaccountname, DomainName, AttemptNum, DateWhenCreated, Notes 
	if($auditFlag) {
		$properties = @{'samaccountname'=$userLogonName;
			'DomainName'=$dcNameParam;
			'AttemptNum'=$attemptNum;
			'DaysLastLoggedInOrCreated'=$numDaysSinceLastLoggedInOrCreated;
			'DateWhenCreated'=$whenCreatedIndividual;
			'LastLogon'=$lastLogonIndividual;
			'Notes'=$errorContent
            }
       $object = New-Object –TypeName PSObject –Prop $properties
	   $global:ListOfIdentifiedAccountsAudit += $object
	}
	return $returnResult
}

# Function that detect Dormant accounts by LastLogon threshold or 1st CreatedDate 
function DetectDormanAccounts($OU, $daysDormantThreshold, $fileToSaveInactiveUser, $fileToSaveAllUsers, $fileToSaveAuditAllusers) {
	#$listUsers = Get-QADUser -SearchRoot $OU
	# Disabled Accounts (userAccountControl:1.2.840.113556.1.4.803:=2), so Not disabled accounts with !
	#Accounts trusted for delegation (userAccountControl:1.2.840.113556.1.4.803:=52)
	#Accounts that are Trust Accounts for Trusted Domains (sAMAccountName=*$)
	if ($filterOutDisabledAccountsInDetection) {
	 $listUsers = Get-QADUser -SizeLimit 3000 -Service $serviceValue -SearchRoot $OU -LdapFilter "(&(objectCategory=person)(!(sAMAccountName=*$))(!userAccountControl:1.2.840.113556.1.4.803:=2))"
	} else {
	 $listUsers = Get-QADUser -SizeLimit 3000 -Service $serviceValue -SearchRoot $OU -LdapFilter "(&(objectCategory=person)(!(sAMAccountName=*$)) )"
	}
	
	
	$lastLogon = $null
	$whenCreated = $null
	
	$datexNumDaysBeforeCurrentDate = ($currentDate).AddDays(0 - $daysDormantThreshold)
	$ListOfIdentifiedDormantAccounts = @() # is because of Export-csv with version 2.0 of Powershell, doesn't support the -append feature. It was added in 3.0.
	$ListOfIdentifiedAccounts = @()
	$queryProblemDetectedBeyondThreshold = $false
	
	foreach ($user in $listUsers) {
			$samAccountName = $user.SamAccountName;
			$isDormant = "False"
			$isDisabled = $user.AccountIsDisabled
			
			$lastLogon = (Get-QADComputer -ComputerRole DomainController -Service $serviceValue | foreach {
			$DCname = $_.Name			
			getUserAttributeByName $DCname "LastLogon" 1 $get_adUser_retry_Attempts $user.LogonName
		} | Measure-Latest)
		    $whenCreated = (Get-QADComputer -ComputerRole DomainController -Service $serviceValue | foreach {
			$DCname = $_.Name
			getUserAttributeByName $DCname "WhenCreated" 1 $get_adUser_retry_Attempts $user.LogonName
			
		} | Measure-Latest)
		
		# At this point, determine if $get_adUser_retry_Attempts threshold was reached on determining
		# lastLogon (don't worry about whenCreated. and if so, don't bother doing
		# Calculation, but add it to a separate problem child list recommending 
		# to rerun script against it as the results may be false.
		# then skip to next user to test. 
		if($global:HashOfProblemAccounts[$samAccountName] -ne $null) {
			# Set a flag that there was a problem with querying certain users on certain domains
			#skip detectection of this user of being dormant due to potential false positive
			$queryProblemDetectedBeyondThreshold = $true
			continue
		}
		if($lastLogon -eq $null) {
		  $numDaysSinceLastLoggedInOrCreated = ($currentDate - $whenCreated).Days
		} else {
		  $numDaysSinceLastLoggedInOrCreated = ($currentDate - $lastLogon).Days
		}
		#Does the calculation to determine if account is dormant.
		if($numDaysSinceLastLoggedInOrCreated - ($daysDormantThreshold ) -gt 0) {
		   #discovered a potentially dormant account
		   $isDormant = "True"
		   $properties = @{'samaccountname'=$samAccountName;
	                'DaysLastLoggedInOrCreated'=$numDaysSinceLastLoggedInOrCreated;
					'DateLastLogon'=$lastLogon; 
					'DateWhenCreated'=$whenCreated;
					'AccountDisabledAlready'=$isDisabled;
	                }
	       $object = New-Object –TypeName PSObject –Prop $properties
		   $ListOfIdentifiedDormantAccounts += $object
		}
		
	    #Debug
		if($debugFlag) {
			Write-Host "username: $samAccountName, Last Logon: $lastLogon, When Created: $whenCreated, $daysDormantThreshold before current Date: $datexNumDaysBeforeCurrentDate, NumDaysSinceLastLoggedOnOrCreated:  $numDaysSinceLastLoggedInOrCreated, AccountDisabledAlready: $isDisabled" 
			$ListOfIdentifiedAccounts += $object
		}
	} #EndForEach
	if($queryProblemDetectedBeyondThreshold) {
	    $global:emailBody += "Script discovered issues with querying certain DC's for certain users during the running of the script. Look at attachment[$potentialDormantUsersNeedingRescan] for further details. Increasing the retry threshold may clear the error."
	}
	$ListOfIdentifiedDormantAccounts| select-object -property samaccountname, DaysLastLoggedInOrCreated, DateLastLogon, DateWhenCreated, AccountDisabledAlready  | Export-csv -NoTypeInformation  $fileToSaveInactiveUser
	
	$global:HashOfProblemAccounts.get_Values() | select-object -property samaccountname, DaysLastLoggedInOrCreated, DateLastLogon, DateWhenCreated, Notes, AccountDisabledAlready  | Export-csv -NoTypeInformation  $pathToEmailAttachmentPotentialDormantUsersNeedingRescan  #global variable for path
	if($debugFlag) {
		$ListOfIdentifiedAccounts| select-object -property samaccountname, DomainName, AttemptNum, Notes, AccountDisabledAlready  | Export-csv -NoTypeInformation  $fileToSaveAllUsers
	}
	if($auditFlag) {
		#	$properties = @{'samaccountname'=$userLogonName;
		#		'DomainName'=$dcNameParam;
		#		'AttemptNum'=$attemptNum;
		#		'Notes'="OK";
	    #        }
		$ListOfIdentifiedAccountsAudit| select-object -property samaccountname, DomainName, AttemptNum, DaysLastLoggedInOrCreated, DateWhenCreated, LastLogon, Notes, AccountDisabledAlready  | Export-csv -NoTypeInformation  $fileToSaveAuditAllusers

	}
}


# get a set of DateTime values from the pipeline
# filter out $nulls and produce the latest of them
# (c) Dmitry Sotnikov
function Measure-Latest {
    BEGIN { $latest = $null }
    PROCESS {
            if (($_ -ne $null) -and (($latest -eq $null) -or ($_ -gt $latest))) {
                $latest = $_ 
            }
    }
    END { $latest }
} 
 
function Measure-Latest2 {
    BEGIN { $latest = $null }
    PROCESS {
			$timeField = $_
            if (($_ -ne $null) -and (($latest -eq $null) -or ($_ -gt $latest))) {
                $latest = $_ 
            }
    }
    END { $latest }
} 


#Refactored method to handle either a single string path to a single attacment or a list of string paths to attachments.
Function sendEmailWithAttachment($emailFromParam, $emailToParam, $emailCCParam, $emailSubjectParam, $emailBodyParam, $pathToEmailAttachmentParam){
	Start-Sleep -Seconds 1
	# Email results

	# attempt to get carraiage returns/line feeds `r`n to be preserved in email body
	$emailBodyParam  = $emailBodyParam | Out-String  # Doesn't appear to help, nor hurt. left as an exercise to troubleshoot later.
	$objMessage = New-Object System.Net.Mail.MailMessage -ArgumentList $emailFromParam, $emailToParam, $emailSubjectParam, $emailBodyParam

	if($emailCCParam -eq "" -or $emailCCParam -eq $null){
	 # don't add CC to email message
	} else {
		$objMessage.CC.Add($emailCCParam);
	}


	#if($emailCC -ne $null -and $emailCC -ne ""){
	#	$objMessage.CC.Add($emailCC);
	#}
	#Add an attachment
	if($pathToEmailAttachmentParam -ne $null -and $pathToEmailAttachmentParam.GetType().Name -eq "String") {
	# If attachment is just a string with the path to one attachment.
		$objAttachment = New-Object System.Net.Mail.Attachment -ArgumentList $pathToEmailAttachmentParam, "Application/Octet";
		$objMessage.Attachments.Add($objAttachment);
	} elseif ( ($pathToEmailAttachmentParam -ne $null) -and ($pathToEmailAttachmentParam.GetType().Name -eq "Object[]") ) {
		foreach ($attachmentPath in $pathToEmailAttachmentParam) {
			$objAttachment = New-Object System.Net.Mail.Attachment -ArgumentList $attachmentPath, "Application/Octet";
			$objMessage.Attachments.Add($objAttachment);
		}
	}

	$smtp = new-object Net.Mail.SmtpClient($smtpServer)
	$smtp.Send($objMessage);
	$objAttachment.Dispose();


}
 
Function Show-Menu { 
 
Param( 
[Parameter(Position=0,Mandatory=$True,HelpMessage="Enter your menu text")] 
[ValidateNotNullOrEmpty()] 
[string]$Menu, 
[Parameter(Position=1)] 
[ValidateNotNullOrEmpty()] 
[string]$Title="Menu", 
[switch]$ClearScreen 
) 
 
if ($ClearScreen) {Clear-Host} 
 
#build the menu prompt 
$menuPrompt=$title 
#add a return 
$menuprompt+="`n" 
#add an underline 
$menuprompt+="-"*$title.Length 
$menuprompt+="`n" 
#add the menu 
$menuPrompt+=$menu 
 
Read-Host -Prompt $menuprompt 
 
} #end function 
 
#define a menu here string 
$menu=@" 
1. Gather List of Inactive Accounts. 
 
2. Disable Inactive Accounts. 
 
3. Delete Disabled Accounts. 
 
Q  Quit 
 
Select a task by number or Q to quit 
"@ 
 
#Keep looping and running the menu until the user selects Q (or q). 
if($runInteractive)
{
	Do { 
	    #use a Switch construct to take action depending on what menu choice 
	    #is selected. 
	                Switch (Show-Menu $menu "Options to locate and remove inactive accounts" -clear) { 
	     "1" 	{
		 			Write-Host "Locating Inactive Accounts.  Please wait..." -ForegroundColor Yellow 
		            #get-qaduser -inactive -DontUseDefaultIncludedProperties -include samaccountname -serializevalues -NotLoggedOnFor $NotLoggedOnFor -sizelimit 0 |  
		            # Export-csv C:\Scripts\Exports\inactive_users.csv 
					DetectDormanAccounts $OU $NotLoggedOnFor $inactiveUserCSVFileAbsolutePath $allUserCSVFileAbsolutePath $auditAllUserCSVFileAbsolutePath
					if($sendEmail){
	   					sendEmailWithAttachment $emailFrom $emailTo $emailCC $emailSubject $emailBody $listOfAttachments
	    			}
	         	}  
	      
	     "2"    {
		            Write-Host "Disabling Inactive Accounts.  Please wait..." -ForegroundColor Red 
	                #import-csv $inactiveUserCSVFileAbsolutePath | foreach{Get-QADUser $_.samaccountname | Disable-QADUser | Set-QADUser -UserPrincipalName "zzz$($_.userprincipalname)"} 
	            	import-csv $inactiveUserCSVFileAbsolutePath | foreach{Get-QADUser -SamAccountName $_.samaccountname -Service $ServiceValue | Disable-QADUser}
				} 
	      
	     "3"    {
		        	Write-Host "Deleting Disabled Accounts.  Please wait..." -ForegroundColor Yellow 
	            	import-csv $inactiveUserCSVFileAbsolutePath | foreach{Get-QADUser -SamAccountName $_.samaccountname -Service $ServiceValue| remove-QADObject} 
	            } 
	      
	     "Q" {Write-Host "Script Terminated" -ForegroundColor Yellow 
	         Return 
	         } 
	      
	     Default {Write-Warning "Invalid Choice. Try again." 
	              sleep -milliseconds 750} 
	    } #switch 
	} While ($True)

} else {
	#Run the Detection Algorithm 
	DetectDormanAccounts $OU $NotLoggedOnFor $inactiveUserCSVFileAbsolutePath $allUserCSVFileAbsolutePath $auditAllUserCSVFileAbsolutePath
	# Function sendEmailWithAttachment($emailFromParam, $emailToParam, $emailCCParam, $emailSubjectParam, $emailBodyParam, $pathToEmailAttachment)
   	if($sendEmail){
   		sendEmailWithAttachment $emailFrom $emailTo $emailCC $emailSubject $emailBody $listOfAttachments
    }
	#Disable the inactive accounts that were found using the Detection Algorithm
	Write-Host "Disabling Inactive Accounts.  Please wait..." -ForegroundColor Red 
	#import-csv $inactiveUserCSVFileAbsolutePath | foreach{Get-QADUser $_.samaccountname | Disable-QADUser | Set-QADUser -UserPrincipalName "zzz$($_.userprincipalname)"} 
	import-csv $inactiveUserCSVFileAbsolutePath | foreach{Get-QADUser -SamAccountName $_.samaccountname -Service $ServiceValue | Disable-QADUser}
}