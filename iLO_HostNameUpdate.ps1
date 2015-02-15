<#
Name: iLO_HostNameUpdate.ps1

Purpose: This script is used to modify the iLO Hostname.
		 This is done by: 
		 Finding available iLOs within the given range
		 Checking if there's a valid DNS entry
		 Checking if the credentials given are valid
		 Checking if the iLO hostname hasn't already been set
		 Setting the iLO hostname
		 
Execution: ./iLO_HostNameUpdate.ps1

Creator: Kyle Ruddy
#>

#Gathering IP Address range
$Range = Read-Host "`nWhat IP address or range should have their iLO hostname updated?"

#Gathering all possible iLOs
$FoundiLO = Find-HPiLO $Range -ErrorAction silentlycontinue -WarningAction silentlycontinue
Write-Host ""

#Verify iLOs were indeed found
if ($FoundiLO -eq $null) {
Write-Host "No iLOs found for that entry.`n"
Exit
}

#Gather the credentials required to authenticate to the iLO system
$creds = Get-Credential -Message "Please enter the credentials required for the iLO/s."

#Loop through the found iLOs
foreach ($ilo in $FoundiLO) { 
$currIP = $ilo.IP

#Verify a DNS entry exists for the current iLO IP
$dnsCheck = Resolve-DNSName $currIP -erroraction silentlycontinue

if ($dnsCheck -eq $null) {Write-Host "$currIP - No DNS entry found for iLO at this IP"}
else {
#Verify iLO status
$currState = Get-HPiLONetworkSetting -Server $currIP -Credential $creds -WarningAction silentlycontinue

if ($currState.Status_Type -eq "ERROR") {Write-Host "$currIP - iLO shows a current status of"$currState.Status_Message}
else{
#Verify what the current iLO Hostname is
$currName = $currState.DNS_Name

#Gather proper formatting of DNS check output
$dnsName = ($dnsCheck.NameHost).Split('.')[0]

if ($currName -notlike $dnsName) {
#Updating iLO Hostname to match DNS name
Set-HPiLONetworkSetting -Server $currIP -DNSName $dnsName -Credential $creds
Write-Host "$currIP - Updated from current name of $currName to $dnsName"
}
if ($currName -like $dnsName) {Write-Host "$currIP - Current name already matches the iLO Hostname"}
}

}

}
Write-Host ""
