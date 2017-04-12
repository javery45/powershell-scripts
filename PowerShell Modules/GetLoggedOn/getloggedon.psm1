#
#
#
#
#
#

Function Get-LoggedOn
{
	[cmdletbinding()]
	param ([string]$ComputerName)
	
	Get-WmiObject win32_computersystem -Computer $ComputerName | select username 
}