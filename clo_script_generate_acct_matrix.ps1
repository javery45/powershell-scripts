#
# Title:	clo_enforcement_script.ps1
# Author:	Justin Avery
# Date:		9/10/14
# Frequency:This script automatically runs Mon-Fri at 7:00pm on SOUTHBROTHER.
# Purpose:	This script searches through the Active Directory database for all user accounts that are CLO Enabled but do not
#			have smartcard required for logon, and turns that requirement on. To ensure that this requirement is applied only to
#			necessarry accounts, this script filters out the following accounts:
#
#			- blank sAMAccountName
#			- computer accounts (ends with $,  e.g. GALAPAGOS$)
#			- user accounts with approved keywords in the description field ("PIN RESET", "SERVICE", "FAILED TOKEN", "NEW TOKEN",
#				"SECONDARY", "GROUP")
#			- user accounts listed in the CLO Exceptions list ("x:\clo_exemption_list_from_pki_token\clo_exempt_list.csv")
#			- disabled accounts
#			- admin accounts (ending in .SA, .MA, .DA, .EA, .PA)
#			- accounts not setup with @smil.mil (e.g. javery@sscpac.srdte.spawar.navy.smil.mil)
#			- accounts missing smartcard EDIPI (e.g. javery@smil.mil)
#			- accounts that are members of a CLO Exceptions group in SSCPAC
#
#			Any remaining accounts that do not have smarcard required for logon will have smartcard enforcement turned on for 
#			their account.
#
# Change log:
#
# 1/14/15 javery removed "CLO Exempt - Administrators" from the CLO Exempt Groups list. This group had been deleted from AD.
# 1/14/15 javery removed "CLO Exempt - SWAN PKI List" from CLO Exempt Groups List. This group was deleted from AD.

# Initialize the date and files for the logs output to be recorded in.
$thedate = (Get-Date -Format MM-dd-yyyy).ToString()
$thetime = (Get-Date -Format HHmm).ToString()
[string]$logfilepath_local = "c:\scripts\logs\clo_enforcement_script_" + $thedate + "_" + $thetime + ".log"
#[string]$logFilepath_network = 
[string]$csvfilepath_local = "c:\scripts\logs\clo_enforcement_script_" + $thedate + "_" + $thetime + ".csv"
$filename = "clo_enforcement_script_" + $thedate + "_" + $thetime + ".csv"
$filename_account_matrix = "account_matrix_" + $thedate + "_" + $thetime + ".csv"
$path = "c:\scripts\logs\" + $filename 
$path_account_matrix = "c:\scripts\logs\" + $filename_account_matrix
New-Item -Path "c:\scripts\logs" -Name $filename -ItemType file 
$header = "date,time,domain,username,fname,lname,enforced,comment1,comment2"
$header | Add-Content $path 

#Region UAC Flag Filtering

Function Global:UserAccountControlFlags
{
	[CmdletBinding()]
	param
	(
	    [Parameter(Mandatory=$true)]
        [int] $Flag				
	)
	
	# Empty Colection
	[String[]]$Flag_Collection = @()

	$PossibleFlags = @{
	"16777216" = "TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION";
	"8388608" = "PASSWORD_EXPIRED";
	"4194304" = "DONT_REQUIRE_PREAUTH";
	"2097152" = "USE_DES_KEY_ONLY";
	"1048576" = "NOT_DELEGATED";
	"524288" = "TRUSTED_FOR_DELEGATION";
	"262144" = "SMARTCARD_REQUIRED";
	"131072" = "MNS_LOGON_ACCOUNT";
	"65536" = "DONT_EXPIRE_PASSWD";
	"8192" = "SERVER_TRUST_ACCOUNT";
	"4096" = "WORKSTATION_TRUST_ACCOUNT";
	"2048" = "INTERDOMAIN_TRUST_ACCOUNT";
	"512" = "NORMAL_ACCOUNT";
	"256" = "TEMP_DUPLICATE_ACCOUNT";
	"128" = "ENCRYPTED_TEXT_PASSWORD_ALLOWED";
	"64" = "PASSWD_CANT_CHANGE";
	"32" = "PASSWD_NOTREQD";
	"16" = "LOCKOUT";
	"8" = "HOMEDIR_REQUIRED";
	"2" = "ACCOUNTDISABLE";
	"1" = "SCRIPT_EXECUTED"
	}
	
	#Sort Keys
	[int32[]]$Keys = $PossibleFlags.Keys
	$Keys = $Keys | sort -Descending
	
	foreach($Key in $Keys)
	{
		if($Flag -ge $Key)
		{
			[string]$Str_Key = $Key
			$Flag_Collection += $PossibleFlags[$Str_Key]
			$Flag = $Flag - $Key
		}
	}
	
	Return $Flag_Collection	
}
#EndRegion UAC Flag Filtering

#Region Import CLO Exception List
# The CLO Exceptions list is maintained by the SwanToken group. This list is updated whenever a new user requests a token, or
# whenever a user requests a replacement token. During that time, the user is added to this Exception List so their SSCPAC account
# may be setup for username/password logon. Once the user receives their token, they are removed from the CLO Exception List
# and their admin is responsible for setting up their SSCPAC account for smartcard logon only. 

#blank collections
$uid = @()
$edipi = @()

#Test to ensure that the CLO Exemption list can be imported successfully
Try
{
#STIG-WINUR-000017 on the file server prevents the next line from working, because .DA credentials cannot talk to the file server to query the csv file
#Import-Csv -Path "\\140.199.56.11\pki_share$\clo_exemption_list_from_pki_token\clo_exempt_list.csv" | ForEach-Object { $uid += $_.uid; $edipi += $_.edipi}

#The workaround for this has been placing the .CSV file locally on the Domain Controller, daily.
Import-Csv -Path "C:\scripts\Task_Scheduled_scripts\clo_exempt_list.csv" | ForEach-Object { $uid += $_.uid; $edipi += $_.edipi}
}
#If the list cannot be imported, terminate the script. User accounts could be mistakenly enforced if the list cannot be read. 
Catch
{
$outputstring = " CLO Exemption List could not be imported. The script will not run."
Write-Output $outputstring
LogContent $outputstring
Exit
Exit-PSSession
Copy-Item -path $path -destination "\\140.199.56.11\pki_share$\clo_exemption_list_from_pki_token\logs"
Exit 

}


#EndRegion Import CLO Exception List

#Region LogContent
# Output from this script is logged for auditing and troubleshooting purposes in two locations: 
# Locally at c:\scripts\logs\clo_enforcement_script.log
# Network Share at \\srdte-fs01\pki share\clo_exemption_list_from_pki_token\logs\clo_enforcement_script.log

Function Global:DateTime
{
	$outputdate = (Get-Date).ToString('d')
	$outputtime = (Get-Date).ToString('T')
}



Function LogContent
{
	[CmdletBinding()]
	param
	(
		[string]$content
	
	) 
	#get date and time strings for file name
	$thedate = (Get-Date -Format MM-dd-yyyy).ToString()
	$thetime = (Get-Date -Format HHmm).ToString()
	
	
	
	#[string]$logFilepath_network = "x:\clo_exemption_list_from_pki_token\logs\clo_enforcement_script.log"
	#[string]$logfilepath_local = "c:\scripts\logs\clo_enforcement_script.log"
	
    #$outputString = (Get-Date).ToString('u') + ": " + $content ;
	$outputstring = $content;
    #$outputString | Add-Content $logFilepath_network;
	$outputstring | Add-Content $logfilepath_local;
	#add output to csv file too
	$outputstring | Add-Content $path 
	
}
#EndRegion	LogContent

#Region Get-DomainGroupMembers

Function Global:Get-DomainGroupMembers
{
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [string]$GroupName,
		
        [parameter(Mandatory=$true)]
		[ValidateSet("SamAccountName", "Path", "Path_Type")]
        [string]$ReturnType,
		
        [parameter(Mandatory=$false)]
        [switch]$Recurse,
		
		[parameter(Mandatory=$true)]
        [string]$TargetDomain
	)	
	
	[psobject[]]$Results = @()	

	#Region Search

	$DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$TargetDomain)
#    $dom = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
#    $GetCurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
#	$GetExternalDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
#	$Trusts = $GetCurrentDomain.GetAllTrustRelationships();
#	$GetExternalTrusts = $Trusts | where{$_.TrustType -match "External"}
#	$ExternalTrusts = $GetExternalTrusts |ForEach-Object{$_.TargetName}$outputString = "WARN: userid: " + $SAMAccountName + ", No Password last Set Property"
    $outputString = "About to call GetDomain on $TargetDomain"
	Write-Host $outputString;
	$dom = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext);
	$root = $dom.GetDirectoryEntry()
	$DomainDirectorySearcher = [System.DirectoryServices.DirectorySearcher]$root
	$DomainDirectorySearcher.pagesize = 2000
	
	$StrFilter = "(&(objectClass=group)(samaccountname=$GroupName))"
	$DomainDirectorySearcher.filter = $StrFilter
	$Group_Search_Results= $DomainDirectorySearcher.findone()

	#EndRegion Search

	if($Group_Search_Results -ne $null)
	{
		[psobject]$GroupObj = $Group_Search_Results.getDirectoryEntry()
		
		[String[]]$MemberPaths = $GroupObj.member
		
		foreach ($MemberPath in $MemberPaths)
		{
			$LDAP_Member = "LDAP://$MemberPath"
		 	$ADSI_Member = [ADSI]$LDAP_Member
	
			$b = 1
			
			# Current Object
			switch ($ReturnType) 
			    { 
			        "SamAccountName"
						{$Results += $ADSI_Member.SamAccountName} 
			        "Path" 
						{$Results += $MemberPath} 
			        "Path_Type" 
						{
							$Addition = New-Object PSObject
							$Addition | Add-Member -type NoteProperty -Name "Path" -Value $MemberPath
							
							if($ADSI_Member.objectClass -contains "Group")
								{$Addition | Add-Member -type NoteProperty -Name "Type" -Value "Group"}
							else
							{
								if($ADSI_Member.objectClass -contains "User")
									{$Addition | Add-Member -type NoteProperty -Name "Type" -Value "User"}
							}
							
							$Results += $Addition
						}
			    }		
			
			# Recurse
			if(($Recurse.IsPresent) -and ($ADSI_Member.objectClass -contains "Group"))
				{$Results += Get-DomainGroupMembers -GroupName $ADSI_Member.SamAccountName -ReturnType $ReturnType -Recurse -TargetDomain $TargetDomain}
			
		}
	}
	
	Return $Results
}
#EndRegion Get-DomainGroupMembers

#Region Populate list of users in CLO Exempt Groups

$clo_groups = "CLO Exempt - Privileged user accounts" 
#blank collection
$clo_exempt_groups = @() 

foreach($group in $clo_groups)
{
	[String[]]$DomainAdmins = Get-DomainGroupMembers -GroupName $group -ReturnType "Path" -TargetDomain "sscpac.srdte.spawar.navy.smil.mil"
	
	foreach($DomainAdmin in $DomainAdmins)
	{
	$LDAP_Member2 = "LDAP://$DomainAdmin"
	$ADSI_Member2 = [ADSI]$LDAP_Member2
	
	$Member_Properties = $ADSI_Member2.Properties 
	$clo_exempt_groups += $Member_Properties.samaccountname
	}
}



#EndRegion Populate list of usrers in CLO Exempt Groups

#Region isNumeric  

function Global:isNumeric
{
	[CmdletBinding()]
	param (
	
		[parameter(Mandatory=$true)]
		[string]$String		
	)
	
    try {
		0 + $String | Out-Null
		return $true
    } 
	
	catch {
		return $false
    }
}
#EndRegion isNumeric 



#$search = New-Object DirectoryServices.DirectorySearcher([ADSI]"LDAP://DC=sscpac,DC=srdte,DC=spawar,DC=navy,DC=smil,DC=mil")
###Search filter grabs all user accounts that DON'T have the keywords "pin reset", "failed token", "service account", "new token", "secondary account", or "group account" in the account's description field.
#$search.Filter = "(& (sAMAccountType=805306368) (!(|(description=*pin reset*)(description=*failed token*)(description=*service account*)(description=*new token*)(description=*secondary account*)(description=*group account*)) ))"
#$results = $search.findall()

$total_unenforced = @()
$total_already_enforced =@()
$total_not_smartcard = @()
[int]$total_users = 0
$clo_exceptions_list_col = @()
$keywords_detected_col = @()
$disabled_accounts_col = @()
$admin_account_col = @()
$not_smil_mil_col = @()
$not_numeric_upn_col = @()
$clo_exempt_group = @()
$smartcard_enforced = @()
$smartcard_unenforced = @()
$not_smartcard_configured = @()

$acct_array = @()
$adm_array = @()

#Region Get All Domain Users
#$Domain_list = @("trident.spawar.navy.smil.mil")
$Domain_list = @("itf.spawar.navy.smil.mil","jedi.spawar.navy.smil.mil","sscpac.srdte.spawar.navy.smil.mil","srdte.spawar.navy.smil.mil")
#$Domain_list = @("sscpac.srdte.spawar.navy.smil.mil","srdte.spawar.navy.smil.mil")
#$Domain_list = @("jaoc.rhino.spawar.navy.smil.mil")
#$Domain_list = @("jedi.spawar.navy.smil.mil")
FOREACH($Domain in $Domain_list)
{
#$rootDSE = [adsi]"LDAP://sscpac.srdte.spawar.navy.smil.mil/RootDSE
$adsi ="LDAP://"+$Domain+"/RootDSE"
$rootDSE = [adsi]$adsi 
$DNSDomain = $rootDSE.defaultNamingContext
$DC = $rootDSE.dnsHostName
$DomainLDAP = "LDAP://$DC/$DNSDomain"
$Root = New-Object DirectoryServices.DirectoryEntry $DomainLDAP
$DomainDirectorySearcher = New-Object DirectoryServices.DirectorySearcher
$DomainDirectorySearcher.searchroot = $root
$DomainDirectorySearcher.pagesize = 2000
$User_search_results = $DomainDirectorySearcher.findall() | where {$_.properties.objectcategory -match "CN=person"}

$DNSDomain_string = $DNSDomain.ToString()
$col1 = $DNSDomain_string.split(",")
$col2 = $col1[0].Split("=")
$DomainName = $col2[1]

#EndRegion Get All Domain Users


Foreach($record in $User_Search_Results)
{
	$LDAP_Member = $Record.path
	$ADSI_Member = [ADSI]$LDAP_Member
	
	$Properties = $ADSI_Member.Properties
	$DName = $Properties.distinguishedname 
	$ADSI_User = [ADSI]"LDAP://$Dname"
	
	$object = New-Object PSObject
	$clo_enabled_flag = $true
	$sa_flag = $false
	$ma_flag = $false 
	$da_flag = $false
	$ea_flag = $false 
	
	# skip any accounts with blank usernames. sAMAccountName should never be blank, but just in case
	if($Properties.samaccountname -ne $null)
	{
		[string]$samaccountname = $Properties.samaccountname
		[string]$userprincipalname = $Properties.userprincipalname
		
		
		
		# skip computers
		if(-not ($samaccountname.EndsWith('$')))
		{
			[string]$description = $Properties.description
			[string]$firstname = $Properties.givenname
			[string]$lastname = $Properties.sn
			
			$object | Add-Member -MemberType NoteProperty -Name "DOMAIN" -Value $Domain
			$object | Add-Member -MemberType NoteProperty -Name "USERNAME" -Value $samaccountname
			$object | Add-Member -MemberType NoteProperty -Name "UPN" -Value $userprincipalname
			
			$object | Add-Member -MemberType NoteProperty -Name "FIRST" -Value $firstname
			$object | Add-Member -MemberType NoteProperty -Name "LAST" -Value $lastname
			
			[int]$flags = $Properties.useraccountcontrol[0]
			$Flag_Results = UserAccountControlFlags -Flag $flags
			
			if ($Flag_Results -notcontains "SMARTCARD_REQUIRED")
			{
			$smartcard_unenforced += $Properties.samaccountname
			
			$outputdate = (Get-Date).ToString('d')
			$outputtime = (Get-Date).ToString('T')
			$outputstring = $outputdate+","+$outputtime+","+$DomainName+","+$samaccountname+","+$firstname+","+$lastname+",--, Smartcard Unenforced,"+$userprincipalname
			Write-Output $outputstring
			LogContent $outputstring
			}
			
			$total_users += 1
			
			#skip any accounts that have the approved KEYWORDS in the description field
			<#
			if ($description -match "pin reset" -or $description -match "service account" -or $description -match "failed token" -or $description -match "token failure" -or $description -match "new token" -or $description -match "secondary" -or $description -match "group")
			{
				#do nothing.
				$keywords_detected_col += $samaccountname
				$outputdate = (Get-Date).ToString('d')
				$outputtime = (Get-Date).ToString('T')
				$outputstring = $outputdate+","+$outputtime+","+$samaccountname+","+$firstname+","+$lastname+",no, keywords detected,"+$description 
				Write-Output $outputstring
				LogContent $outputstring 
			}  #>
			<#
			ELSE
			{  #>
				# skip any users listed on the CLO Exceptions List. The CSV file for this list is first imported, and the appropriate values are put in variable lists.
				if ($uid -notcontains $Properties.samaccountname)
				{
					#$Properties.samaccountname
					
				
					 
					
					
					
						# skip DA and EA admin accounts
						IF ( ( $samaccountname.ToLower().EndsWith(".da")) -or ( $samaccountname.ToLower().EndsWith(".ea")))
						{ 
							# It is an admin account. Do not alter the account
							$admin_account_col += $samaccountname
							#$outputstring = $samaccountname + " will not be enforced. Administrative account detected."
							$outputdate = (Get-Date).ToString('d')
							$outputtime = (Get-Date).ToString('T')
							$outputstring = $outputdate+","+$outputtime+","+$DomainName+","+$samaccountname+","+$firstname+","+$lastname+",no, DA or EA Administrative account detected"
							Write-Output $outputstring
							LogContent $outputstring 
							
						}
						ELSE
						{ 
							# Continue to process the account
						
							# @SMIL.MIL
							If ($userprincipalname.tolower().endswith("@smil.mil"))
							{
								#$Properties.samaccountname + "is partially set for CLO"
								$HoldCol = $userprincipalname.split("@")
								$HoldCol2 = $HoldCol[0].split(".")
								
								# Check if everything on the left side of @smil.mil is numeric, indicating that a SIPR Token has been associated with this account
								if ((isnumeric -String $HoldCol2[0]))
								{
									
									
									# Check if the user is a member of a CLO Exception group in Active Directory
									if ($clo_exempt_groups -notcontains $Properties.samaccountname)
									{
										# Check if the account is missing the check box for "Smartcard required"
										if ($Flag_Results -notcontains "SMARTCARD_REQUIRED")
										{
											$total_unenforced += $samaccountname 
											
										
											[int]$uac = $Properties.useraccountcontrol.tostring()
											
											
											# Log data
											#$outputstring = $samaccountname + " " + CLO enforcement has been turned on
											#$outputstring = $samaccountname + "," + $Properties.givenname + " " + $Properties.sn 
											$outputdate = (Get-Date).ToString('d')
											$outputtime = (Get-Date).ToString('T')
											$outputstring = $outputdate+","+$outputtime+","+$DomainName+","+$samaccountname+","+$firstname+","+$lastname+",yes, CLO has been enforced on this account"
											Write-Output $outputstring
											LogContent $outputstring 
											
											
											#THIS IS WHERE THE ENFORCEMENT BLOCK WOULD HAVE BEEN.
											
										}
										else
										{
											$total_already_enforced += $samaccountname
											
											[int]$uac = $Properties.useraccountcontrol.tostring()
											
											$outputdate = (Get-Date).ToString('d')
											$outputtime = (Get-Date).ToString('T')
											$outputstring = $outputdate+","+$outputtime+","+$DomainName+","+$samaccountname+","+$firstname+","+$lastname+",no, account is already setup for CLO enforcement"
											Write-Output $outputstring
											LogContent $outputstring 
										}
									
									}
									ELSE
									{
									$clo_exempt_group += $samaccountname
									#$outputstring = $samaccountname + " will not be enforced. They are a member of a CLO exempt group in Active Directory."
									$outputdate = (Get-Date).ToString('d')
									$outputtime = (Get-Date).ToString('T')
									$outputstring = $outputdate+","+$outputtime+","+$DomainName+","+$samaccountname+","+$firstname+","+$lastname+",no, Member of CLO exempt group in Active Directory"
									Write-Output $outputstring
									LogContent $outputstring 
									}
								}
								#Users not set up properly for smart card. UPN is not numeric.
								ELSE
								{
									$not_numeric_upn_col += $samaccountname
									$total_not_smartcard += $samaccountname 
									#$outputstring = $samaccountname + " will not be enforced. UserPrincipalName attribute is not configured for EDIPI. Non-numerical value detected."
									$outputdate = (Get-Date).ToString('d')
									$outputtime = (Get-Date).ToString('T')
									$outputstring = $outputdate+","+$outputtime+","+$DomainName+","+$samaccountname+","+$firstname+","+$lastname+",no, Non-numerical EDIPI value detected."
									Write-Output $outputstring
									LogContent $outputstring 
								}
								
							#Users not set up properly for smart card. Doesn't end with @smil.mil
							}
							ELSE
							{
								# The account does not end in @SMIL.MIL, it doesn't make sense to enforce it.
								$not_smil_mil_col += $samaccountname
								$total_not_smartcard += $samaccountname 
								#$outputstring = $samaccountname + " will not be enforced. UserPrincipalName attribute is not configured for @SMIL.MIL."
								$outputdate = (Get-Date).ToString('d')
								$outputtime = (Get-Date).ToString('T')
								$outputstring = $outputdate+","+$outputtime+","+$DomainName+","+$samaccountname+","+$firstname+","+$lastname+",no, UserPrincipalName attribute not configured for @SMIL.MIL."
									Write-Output $outputstring
									LogContent $outputstring 
							}
						
						} 
							
					
					
					
					
				}
				ELSE
				{
				$clo_exceptions_list_col += $samaccountname
				#$outputstring = $samaccountname + " will not be enforced. User is a member of a CLO exempt account in Active Directory."
				$outputdate = (Get-Date).ToString('d')
				$outputtime = (Get-Date).ToString('T')
				$outputstring = $outputdate+","+$outputtime+","+$DomainName+","+$samaccountname+","+$firstname+","+$lastname+",no, Member of CLO exempt group in Active Directory"
				Write-Output $outputstring
				LogContent $outputstring 
				}
				#$Properties.samaccountname
				#$Properties.description 
				#$Flag_Results
				#Write-Host " "
			<#	
			} #>
		
		#START COUNT OF NON-SMARTCARD ENABLED ACCOUNTS
		
		If ($userprincipalname.tolower().endswith("@smil.mil"))
		{
			
			$HoldCol = $userprincipalname.split("@")
			$HoldCol2 = $HoldCol[0].split(".")
			
			$object | Add-Member -MemberType NoteProperty -Name "SMIL.MIL" -Value $true							
										
			# Check if everything on the left side of @smil.mil is numeric, indicating that a SIPR Token has been associated with this account
			if ((isnumeric -String $HoldCol2[0]))
			{
				$is_smartcard_configured += $Properties.samaccountname
			
				$object | Add-Member -MemberType NoteProperty -Name "NUMERICAL UPN" -Value $true	
			
				$outputdate = (Get-Date).ToString('d')
				$outputtime = (Get-Date).ToString('T')
				$outputstring = $outputdate+","+$outputtime+","+$DomainName+","+$samaccountname+","+$firstname+","+$lastname+",--, Is Smartcard Configured,"+$userprincipalname
				Write-Output $outputstring
				LogContent $outputstring
			}
			else
			{
				$not_smartcard_configured += $Properties.samaccountname
				
				$object | Add-Member -MemberType NoteProperty -Name "NUMERICAL UPN" -Value $false 
				
				$clo_enabled_flag = $false
				
				$outputdate = (Get-Date).ToString('d')
				$outputtime = (Get-Date).ToString('T')
				$outputstring = $outputdate+","+$outputtime+","+$DomainName+","+$samaccountname+","+$firstname+","+$lastname+",--, Not Smartcard Configured,"+$userprincipalname
				Write-Output $outputstring
				LogContent $outputstring
			}
			
		}
		else
		{
		$not_smartcard_configured += $Properties.samaccountname
		
		$object | Add-Member -MemberType NoteProperty -Name "SMIL.MIL" -Value $false
		$clo_enabled_flag = $false 
				
		$outputdate = (Get-Date).ToString('d')
		$outputtime = (Get-Date).ToString('T')
		$outputstring = $outputdate+","+$outputtime+","+$DomainName+","+$samaccountname+","+$firstname+","+$lastname+",--, Not Smartcard Configured,"+$userprincipalname
		Write-Output $outputstring
		LogContent $outputstring
		}
		
		#END COUNT
		
		}
		ELSE
		{
			continue
		}
	}
	
	if ($Flag_Results -contains "SMARTCARD_REQUIRED")
	{
		$smartcard_enforced += $Properties.samaccountname
		
		$object | Add-Member -MemberType NoteProperty -Name "CLO ENFORCED" -Value $true	
	}
	else
	{
		$object | Add-Member -MemberType NoteProperty -Name "CLO ENFORCED" -Value $false
	}
	
	
	if ($Flag_Results -notcontains "SMARTCARD_REQUIRED")
	{
		if(-not ($samaccountname.EndsWith('$')))
		{
			# $smartcard_unenforced += $Properties.samaccountname 
		
			IF ( ( $samaccountname.ToLower().EndsWith(".sa")) -or ( $samaccountname.ToLower().EndsWith(".ma")) -or ( $samaccountname.ToLower().EndsWith(".da")) -or ( $samaccountname.ToLower().EndsWith(".ea")))
			{
				#do nothing
			}
			ELSE
			{
				<#IF ($Flag_Results -notcontains "ACCOUNTDISABLE")
				{#>
					[string]$samaccountname = $Properties.samaccountname
					[string]$userprincipalname = $Properties.userprincipalname
					
					
					$outputdate = (Get-Date).ToString('d')
					$outputtime = (Get-Date).ToString('T')
					$outputstring = $outputdate+","+$outputtime+","+$DomainName+","+$samaccountname+","+$firstname+","+$lastname+",no, Smartcard is not enforced."
					Write-Output $outputstring
					LogContent $outputstring 
				<#}#>
			}
		}
	}
	
	
	IF ( ( $samaccountname.ToLower().EndsWith(".sa")) -or ( $samaccountname.ToLower().EndsWith(".ma")) -or ( $samaccountname.ToLower().EndsWith(".da")) -or ( $samaccountname.ToLower().EndsWith(".ea")))
	{
		[string]$samaccountname = $Properties.samaccountname
		[string]$userprincipalname = $Properties.userprincipalname
		
		$object | Add-Member -MemberType NoteProperty -Name "ADMINISTRATOR" -Value $true			
		
		IF($samaccountname.ToLower().EndsWith(".sa"))
		{
			$sa_flag = $true 
		}
		IF($samaccountname.ToLower().EndsWith(".ma"))
		{
			$ma_flag = $true 
		}
		IF($samaccountname.ToLower().EndsWith(".da"))
		{
			$da_flag = $true 
		}
		IF($samaccountname.ToLower().EndsWith(".ea"))
		{
			$ea_flag = $true 
		}
					
		$outputdate = (Get-Date).ToString('d')
		$outputtime = (Get-Date).ToString('T')
		$outputstring = $outputdate+","+$outputtime+","+$DomainName+","+$samaccountname+","+$firstname+","+$lastname+",--, _IA ADMIN ACCOUNTS LIST_"
		Write-Output $outputstring
		LogContent $outputstring 
		
		$obj = New-Object PSObject
		$obj | Add-Member -MemberType NoteProperty -Name "USERID" -Value $samaccountname
		$obj | Add-Member -MemberType NoteProperty -Name "FIRST" -Value $firstname
		$obj | Add-Member -MemberType NoteProperty -Name "LAST" -Value $lastname
		$obj | Add-Member -MemberType NoteProperty -Name "DOMAIN" -Value $DomainName
		
		$adm_array += $obj 
	}
	else
	{
		$object | Add-Member -MemberType NoteProperty -Name "ADMINISTRATOR" -Value $false
	}
	
	$object | Add-Member -MemberType NoteProperty -Name "SA" -Value $sa_flag
	$object | Add-Member -MemberType NoteProperty -Name "MA" -Value $ma_flag
	$object | Add-Member -MemberType NoteProperty -Name "DA" -Value $da_flag
	$object | Add-Member -MemberType NoteProperty -Name "EA" -Value $ea_flag
	
	if ($Flag_Results -contains "ACCOUNTDISABLE")
	{
		$disabled_accounts_col += $Properties.samaccountname
		
		$object | Add-Member -MemberType NoteProperty -Name "DISABLED" -Value $true
	}
	else
	{
		$object | Add-Member -MemberType NoteProperty -Name "DISABLED" -Value $false
	}
	
	if ($clo_enabled_flag -eq $true)
	{
		$object | Add-Member -MemberType NoteProperty -Name "CLO ENABLED" -Value $true	
	}
	else
	{
		$object | Add-Member -MemberType NoteProperty -Name "CLO ENABLED" -Value $false 
	}
#	$user = $result.GetDirectoryEntry()
	#[int]$flags = $user.userAccountControl
	#[String[]]$flags = UserAccountControlFlags -Flag $flags
	
	#$user.distinguishedname
#	$user.name
	#$user.distinguishedName
#	$user.description
#	$user.sAMAccountName
#	$user.userAccountControl
	#$userid += $user.sAMAccountName
#	Write-Host " "

	$acct_array += $object 

}
}


$acct_array | Export-Csv $path_account_matrix -NoTypeInformation
#output totals from collections

$outputstring = "----------------------------------------"
Write-Output $outputstring
LogContent $outputstring

$outputstring = "Accounts in CLO Exceptions List: " + $clo_exceptions_list_col.count 
Write-Output $outputstring
LogContent $outputstring 

$outputstring = "Accounts with Keywords: " + $keywords_detected_col.count
Write-Output $outputstring
LogContent $outputstring 

$outputstring = "Disabled Accounts: " + $disabled_accounts_col.count
Write-Output $outputstring
LogContent $outputstring 

$outputstring = "Admin Accounts: " + $adm_array.Count 
Write-Output $outputstring
LogContent $outputstring 

$outputstring = "@SMIL.MIL not selected: " + $not_smil_mil_col.count
Write-Output $outputstring
LogContent $outputstring 

$outputstring = "Non-numeric UPN: " + $not_numeric_upn_col.count
Write-Output $outputstring
LogContent $outputstring 

$outputstring = "CLO Exempt Group Members: " + $clo_exempt_group.count 
Write-Output $outputstring
LogContent $outputstring 

$outputstring = "----------------------------------------"
Write-Output $outputstring
LogContent $outputstring

$outputstring = "Total accounts enforced by this script: " + $total_unenforced.Count 
Write-Output $outputstring
LogContent $outputstring 

$outputstring = "----------------------------------------"
Write-Output $outputstring
LogContent $outputstring

$outputstring = "Total accounts already enforced: " + $smartcard_enforced.Count  
Write-Output $outputstring
LogContent $outputstring

$outputstring = "Total accounts unenforced: " + $smartcard_unenforced.Count 
Write-Output $outputstring
LogContent $outputstring

$outputstring = "TOTAL USER ACCOUNTS: " + $total_users.ToString()
Write-Output $outputstring
LogContent $outputstring

$outputstring = "----------------------------------------"
Write-Output $outputstring
LogContent $outputstring

$adm_array_path = "c:\scripts\logs\Admin_Account_List_"+$thedate+"_"+$thetime+".csv"
$adm_array | Export-Csv $adm_array_path -NoTypeInformation 

#Region Email Body Format

$formatted_list = ""
$formatted_list_admins = ""
$formatted_list_admins_count = 0
$formatted_list_users = ""
$formatted_list_users_count = 0

FOREACH($item in $not_smartcard_configured)
{
	$formatted_list += ($item+"<br>")
	
	IF ( ( $item.ToLower().EndsWith(".sa")) -or ( $item.ToLower().EndsWith(".ma")))# -or ( $item.ToLower().EndsWith(".da")) -or ( $item.ToLower().EndsWith(".ea")))
	{
		$formatted_list_admins += ($item+"<br>")
		$formatted_list_admins_count += 1
	}
	ELSE
	{
		$formatted_list_users += ($item+"<br>")
		$formatted_list_users_count += 1
	}
}



#EndRegion Email Body Format

#Region Email Configuration

$emailFrom = "swan_windows_admins@spawar.navy.smil.mil"
$emailTo = "swan_windows_admins@spawar.navy.smil.mil"
$emailCC = "dgauldin@spawar.navy.smil.mil"
$emailSubject = "Report of SRDTE & SSCPAC domain accounts - "+$thedate
#$emailBody = "TOTAL ACCOUNTS NOT SMARTCARD CONFIGURED (" + $not_smartcard_configured.Count + ")<br>" + $formatted_list + "<br><br> ADMIN ACCOUNTS NOT SMARTCARD CONFIGURED (" + $formatted_list_admins_count + ")<br>" + $formatted_list_admins
$emailBody = "TOTAL ACCOUNTS NOT SMARTCARD CONFIGURED (" + $not_smartcard_configured.Count.ToString() + "):<br>" + $formatted_list + "<br>ADMIN SA & MA ACCOUNTS NOT SMARTCARD CONFIGURED (" + $formatted_list_admins_count.ToString() + "):<br>" + $formatted_list_admins + "<br>OTHER ACCOUNTS NOT SMARTCARD CONFIGURED (" + $formatted_list_users_count.ToString() + "):<br>" + $formatted_list_users
#$pathToEmailAttachment = $adm_array_path
$pathToEmailAttachment = $path_account_matrix
$global:smtpServer = "smtp.spawar.navy.smil.mil"

#EndRegion Email Configuration

Function sendEmailWithAttachment ($emailFromParam, $emailToParam, $emailCCParam, $emailSubjectParam, $emailBodyParam, $pathToEmailAttachmentParam)
{

Start-Sleep -Seconds 1

$emailBodyParam = $emailBodyParam | Out-String
$objMessage = New-Object System.Net.Mail.MailMessage -ArgumentList $emailFromParam, $emailToParam, $emailSubjectParam, $emailBodyParam

	$objMessage.IsBodyHTML = $true

	if($emailCCParam -eq "" -or $emailCCParam -eq $null)
	{
		#don't add CC to email
	}
	else
	{
		$objMessage.CC.Add($emailCCParam);
	}

	if($pathToEmailAttachmentParam -ne $null -and $pathToEmailAttachmentParam.GetType().Name -eq "String")
	{
		$objAttachment = New-Object System.Net.Mail.Attachment -ArgumentList $pathToEmailAttachmentParam, "Application/Octet";
		$objMessage.Attachments.Add($objAttachment);
	}
$smtp = New-Object Net.Mail.SmtpClient ($smtpServer)
$smtp.Send($objMessage);
$objAttachment.Dispose();

}

#send the email
sendEmailWithAttachment $emailFrom $emailTo $emailCC $emailSubject $emailBody $pathToEmailAttachment


# copy the local log file and store it on the network location
#Copy-Item -path "c:\scripts\logs\clo_enforcement_script.log" -destination "\\140.199.56.11\pki_share$\clo_exemption_list_from_pki_token\logs"
#copy the local csv file and store in on the network location in the PKI Share shared drive
Copy-Item -path $path -destination "\\140.199.56.11\pki_share$\clo_exemption_list_from_pki_token\logs"
#copy the local csv file and store in on the network location in the SWAN IA shared drive
Copy-Item -path $path -destination "\\140.199.56.11\swan_ia$\clo\clo_exemption_management\logs"
