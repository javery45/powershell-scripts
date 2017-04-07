# Author:  Justin Avery
# Date:    04/07/2017
# Description: This is a PowerShell function that queries a remote system and returns the name of the logged in user. If the returned result is blank, no user is logged in.

function Get-LoggedOn ($computerName)
{
    Get-WmiObject -Class win32_computersystem -ComputerName $computerName | select username
}