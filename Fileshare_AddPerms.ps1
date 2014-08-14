<#
Name: Fileshare_AddPerms.ps1

Purpose: Adding new File Share level permissions to an existing file share
		 
Execution: ./FileshareAddPerms.ps1

Creator: Kyle Ruddy		 
#>

#Workload specific variables
$fileshare = "FileShareName"
$adddomain = "consoto"
$addgroup = "FileShareGroup"
$AddRights = "Full Control"
$computers = Get-ADComputer -SearchBase 'ou=FileShares,ou=Computers,dc=contoso,dc=local' -Filter * | sort Name 

#Constant Variables
$MaximumAllowed = [System.UInt32]::MaxValue
if ($AddRights = "Full Control") {$AddAccess = '2032127'}
elseif ($AddRights = "Change") {$AddAccess = '1245631'}
else {$AddAccess = '1179817'}
$results = @()

foreach ($comp in $computers) {
$Share = $SecSettings = $SecDACLs = $null
$AdjustedPath = "*" + $comp.Name + "*" + $fileshare

#Grabbing Share Information
$Share = Get-WmiObject -Class "Win32_Share" -ComputerName $comp.Name -ErrorAction SilentlyContinue | where {$_.Name -like $AdjustedPath} 

#Testing whether share exists  
if ($Share -ne $null) {
$ace = $trustee = $description = $null
$aces = @()

#Establishing Description on file share
$description = $Share.Description
if ($description -eq $null) {$description = ""}

#Pulling and storing file share security information based on the desired file share
$SecSettings = Get-WmiObject win32_logicalsharesecuritysetting -ComputerName $comp.Name | where {$_.Name -like $AdjustedPath} 
$SecDescriptor = $SecSettings.GetSecurityDescriptor()
$SecDACLs = ($SecDescriptor.Descriptor).DACL

#Verifying the user or group is not already granted rights to the file share
if ($SecDACLs.Trustee.Name -notcontains $addgroup) {

#Adding desired credentials as a trustee
$trustee = ([wmiclass]‘Win32_trustee’).psbase.CreateInstance()
$trustee.Domain = $AddDomain
$trustee.Name = $AddGroup

#Adding desired credentials and setting access level to ACE
$ace = ([wmiclass]‘Win32_ACE’).psbase.CreateInstance()
$ace.AccessMask = $AddAccess
$ace.AceFlags = 3
$ace.AceType = 0
$ace.Trustee = $trustee

$aces += $ace

#Pulling existing DACLs on the file share
foreach ($dacl in $SecDACLs) {
$ace = $trustee = $null

$trustee = ([wmiclass]‘Win32_trustee’).psbase.CreateInstance()
$trustee.Domain = $dacl.Trustee.Domain
$trustee.Name = $dacl.Trustee.Name

$ace = ([wmiclass]‘Win32_ACE’).psbase.CreateInstance()
$ace.AccessMask = $dacl.AccessMask
$ace.AceFlags = 3
$ace.AceType = 0
$ace.Trustee = $trustee

$aces += $ace

}

#Creating and setting the Security Descriptor including the new DACL
$sd = ([wmiclass]‘Win32_SecurityDescriptor’).psbase.CreateInstance()
$sd.ControlFlags = 4
$sd.DACL = $aces

#Setting the Security Descriptor on the file share
$Share.SetShareInfo($MaximumAllowed, $description, $sd) | Out-Null
Write-Host $comp.Name "- $AddGroup permissions have been assigned to $fileshare." -ForegroundColor Green
$tempresults = "" | select Name,Result
$tempresults.Name = $comp.Name
$tempresults.Result = "Perms Added"
$results += $tempresults
}
else {Write-Host $comp.Name "-" $fileshare "already has $AddGroup permissions assigned."
$tempresults = "" | select Name,Result
$tempresults.Name = $comp.Name
$tempresults.Result = "Perms Exist"
$results += $tempresults
}

}
else {Write-Host $comp.Name "- does not have file share - $fileshare" -ForegroundColor Red
$tempresults = "" | select Name,Result
$tempresults.Name = $comp.Name
$tempresults.Result = "No Share"
$results += $tempresults
}

}
$results
