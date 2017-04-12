#
#
#
#
#
#


Function Force-LogOff
{
	
	[cmdletbinding()]
	param ([string]$ComputerName)
	
	$LoggedOnUser = Get-WmiObject win32_computersystem -Computer $ComputerName | select username 
	
	IF($LoggedOnUser.username -eq $null) #If no one is logged on
	{
		TRY{
		(gwmi win32_operatingsystem -ComputerName $ComputerName).win32ShutDown(4)
		}
		CATCH{
		Write-Host "No user is logged in on" + $ComputerName 
		}
	}
	ELSE #Someone is logged on
	{
		$answer = Read-Host "User " $LoggedOnUser.username "is currently logged on to" $ComputerName "do you want to force log them off? <Y/N>"
	
		IF($answer.ToLower() -eq "y")
		{
			TRY{
			(gwmi win32_operatingsystem -ComputerName $ComputerName).win32ShutDown(4)
			
			Write-Host $LoggedOnUser.username is being logged off
			}
			CATCH{
			Write-Host "No user is logged in on" + $ComputerName 
			}
		}
		ELSE
		{
			Break
		}
	}
}
