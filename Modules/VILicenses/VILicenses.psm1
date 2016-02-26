function Get-VILicenses {
<#  
.SYNOPSIS  
    Gathers information on all VI licenses
.DESCRIPTION 
    Will inventory all of the licenses available
.NOTES  
    Author:  Kyle Ruddy, @kmruddy, thatcouldbeaproblem.com
.PARAMETER Used
    True or False, used in order to see only used licenses
.PARAMETER NotUsed
    True or False, used in order to see only nonused licenses
.PARAMETER Expiring
    True or False, used in order to see only expiring licenses
.EXAMPLE
    Get-VILicenses
    Shows all available licenses in the vCenter Server's inventory
.EXAMPLE
    Get-VILicenses -Used $true
    Shows all licenses currently in use in the vCenter Server's inventory
.EXAMPLE
    Get-VILicenses -NotUsed $true
    Shows all licenses currently not in use in the vCenter Server's inventory
.EXAMPLE
    Get-VILicenses -Expiring $true
    Shows all licenses which will expire in 60 days that are in the vCenter Server's inventory
#>
[CmdletBinding()] 
	param(
		[Parameter(Mandatory=$false,Position=0)]
		[Boolean]$Used = $false,
		[Parameter(Mandatory=$false,Position=1)]
		[Boolean]$NotUsed = $false,
		[Parameter(Mandatory=$false,Position=2)]
		[Boolean]$Expiring = $false
  	)

	Process {

    if (!$global:DefaultVIServer -or $global:DefaultVIServer.IsConnected -eq $false) {Write-Error "`nNo valid vCenter Server connection found. Please connect to the vCenter Server and try again."}
    else {
        $svcinst = Get-View ServiceInstance
        $licmgr = Get-View $svcinst.Content.LicenseManager

        if ($notused -eq $true) {$licenses = $licmgr.Licenses | ?{$_.Used -eq "0"}}
        elseif ($used -eq $true) {$licenses = $licmgr.Licenses | ?{$_.Used -gt "0"}}
        else {$licenses = $licmgr.Licenses}
	
        $lreport = @()
	    foreach ($lic in $licenses)
		    {
            
            if ($lic.Name -notlike "*Evaluation*") {

		        $l = New-Object System.Object
		        $l | Add-Member -Type NoteProperty -Name Name -Value $lic.Name
                $l | Add-Member -Type NoteProperty -Name Version -Value ($lic.Properties | ?{$_.Key -eq "ProductVersion"}).Value
		        $l | Add-Member -Type NoteProperty -Name Key -Value $lic.LicenseKey
		        if (!$lic.Used) {$l | Add-Member -Type NoteProperty -Name Used -Value "0"}
                else {$l | Add-Member -Type NoteProperty -Name Used -Value $lic.Used}
                $l | Add-Member -Type NoteProperty -Name Total -Value $lic.Total
                if ($lic.CostUnit -eq "cpuPackage") {$l | Add-Member -Type NoteProperty -Name Unit -Value "CPUs"}
                elseif ($lic.CostUnit -eq "vm") {$l | Add-Member -Type NoteProperty -Name Unit -Value "VMs"}
                elseif ($lic.CostUnit -eq "server") {$l | Add-Member -Type NoteProperty -Name Unit -Value "Instances"}
                $expire = ($lic.Properties | ?{$_.Key -eq "expirationDate"}).Value
		        if (!$expire) {$l | Add-Member -Type NoteProperty -Name Expiration -Value $null}
                else {$l | Add-Member -Type NoteProperty -Name Expiration -Value (Get-Date $expire -format d)}

                if ($expiring -eq $true) {if ($expire -lt (get-date).AddDays(60)) {$lreport += $l}}
                else {$lreport += $l}
            }
		    }
	    $lreport | % { $_.PSObject.TypeNames.Insert(0,"VIObject.License") }
	    return $lreport
    }
	} # End of process
} # End of function

function Get-VILicenseInfo {
<#  
.SYNOPSIS  
    Gathers information on the supplied license key
.DESCRIPTION 
    Will inventory the provided license key
.NOTES  
    Author:  Kyle Ruddy, @kmruddy, thatcouldbeaproblem.com
.PARAMETER Key
    License key to be used
.EXAMPLE
	Get-VILicenseInfo -Key xxxxx-xxxxx-xxxxx-xxxxx-xxxxx
    Gathers information about the supplied key
#>
[CmdletBinding()] 
	param(
		[Parameter(Mandatory=$true,Position=0,ValueFromPipelineByPropertyName=$true)]
        [ValidatePattern(“^\w{5}-\w{5}-\w{5}-\w{5}-\w{5}”)]
		[String]$Key
  	)

	Process {

    if (!$global:DefaultVIServer -or $global:DefaultVIServer.IsConnected -eq $false) {Write-Error "`nNo valid vCenter Server connection found. Please connect to the vCenter Server and try again."}
    else {

    $svcinst = Get-View ServiceInstance
    $licmgr = Get-View $svcinst.Content.LicenseManager

    $licenses = $licmgr.DecodeLicense($Key)
	
    $lreport = @()
	foreach ($lic in $licenses)
		{
		$l = New-Object System.Object
		$l | Add-Member -Type NoteProperty -Name Name -Value $lic.Name
        $l | Add-Member -Type NoteProperty -Name Version -Value ($lic.Properties | ?{$_.Key -eq "ProductVersion"}).Value
		$l | Add-Member -Type NoteProperty -Name Key -Value $lic.LicenseKey
		if (!$lic.Used) {$l | Add-Member -Type NoteProperty -Name Used -Value "0"}
        else {$l | Add-Member -Type NoteProperty -Name Used -Value $lic.Used}
        $l | Add-Member -Type NoteProperty -Name Total -Value $lic.Total
        if ($lic.CostUnit -eq "cpuPackage") {$l | Add-Member -Type NoteProperty -Name Unit -Value "CPUs"}
        elseif ($lic.CostUnit -eq "vm") {$l | Add-Member -Type NoteProperty -Name Unit -Value "VMs"}
        elseif ($lic.CostUnit -eq "server") {$l | Add-Member -Type NoteProperty -Name Unit -Value "Instances"}
        else {$l | Add-Member -Type NoteProperty -Name Unit -Value ""}
        $expire = ($lic.Properties | ?{$_.Key -eq "expirationDate"}).Value
		if (!$expire) {$l | Add-Member -Type NoteProperty -Name Expiration -Value ""}
        else {$l | Add-Member -Type NoteProperty -Name Expiration -Value (Get-Date $expire -format d)}
        
        $lreport += $l
		}
	$lreport | % { $_.PSObject.TypeNames.Insert(0,"VIObject.License") }
	return $lreport

    }
	} # End of process
} # End of function

function Add-VILicense {
<#  
.SYNOPSIS  
    Adds the supplied license key to the license inventory
.DESCRIPTION 
    Will add the provided license key to the inventory
.NOTES  
    Author:  Kyle Ruddy, @kmruddy, thatcouldbeaproblem.com
.PARAMETER Key
    License key to be used
.EXAMPLE
	Add-VILicenseInfo -Key xxxxx-xxxxx-xxxxx-xxxxx-xxxxx
    Adds the supplied key to the vCenter Server's inventory
.EXAMPLE
	Get-VILicenseInfo -Key xxxxx-xxxxx-xxxxx-xxxxx-xxxxx | Add-VILicenseInfo
    Adds the supplied key to the vCenter Server's inventory
#>
[CmdletBinding()] 
	param(
		[Parameter(Mandatory=$true,Position=0,ValueFromPipelineByPropertyName=$true)]
        [ValidatePattern(“^\S{5}-\S{5}-\S{5}-\S{5}-\S{5}”)]
		[String]$Key
  	)

	Process {

    if (!$global:DefaultVIServer -or $global:DefaultVIServer.IsConnected -eq $false) {Write-Error "`nNo valid vCenter Server connection found. Please connect to the vCenter Server and try again."}
    else {

        $svcinst = Get-View ServiceInstance
        $licmgr = Get-View $svcinst.Content.LicenseManager

        $licenses = $licmgr.DecodeLicense($Key)
        if (!$licenses.LicenseKey) {Write-Error "`n$key - Valid license not found."}
        else {
	
        $output = $licmgr.AddLicense($Key, $null)

        $lreport = @()
	    foreach ($lic in $output)
		    {
		    $l = New-Object System.Object
		    $l | Add-Member -Type NoteProperty -Name Name -Value $lic.Name
            $l | Add-Member -Type NoteProperty -Name Version -Value ($lic.Properties | ?{$_.Key -eq "ProductVersion"}).Value
		    $l | Add-Member -Type NoteProperty -Name Key -Value $lic.LicenseKey
		    if (!$lic.Used) {$l | Add-Member -Type NoteProperty -Name Used -Value "0"}
            else {$l | Add-Member -Type NoteProperty -Name Used -Value $lic.Used}
            $l | Add-Member -Type NoteProperty -Name Total -Value $lic.Total
            if ($lic.CostUnit -eq "cpuPackage") {$l | Add-Member -Type NoteProperty -Name Unit -Value "CPUs"}
            elseif ($lic.CostUnit -eq "vm") {$l | Add-Member -Type NoteProperty -Name Unit -Value "VMs"}
            elseif ($lic.CostUnit -eq "server") {$l | Add-Member -Type NoteProperty -Name Unit -Value "Instances"}
            $expire = ($lic.Properties | ?{$_.Key -eq "expirationDate"}).Value
		    if (!$expire) {$l | Add-Member -Type NoteProperty -Name Expiration -Value $null}
            else {$l | Add-Member -Type NoteProperty -Name Expiration -Value (Get-Date $expire -format d)}
        
            $lreport += $l
		    }
	    $lreport | % { $_.PSObject.TypeNames.Insert(0,"VIObject.License") }
	    return $lreport
        }
	}
    } # End of process
} # End of function

function Remove-VILicense {
<#  
.SYNOPSIS  
    Removes the supplied license key from the license inventory
.DESCRIPTION 
    Will remove the provided license key from the inventory
.NOTES  
    Author:  Kyle Ruddy, @kmruddy, thatcouldbeaproblem.com
.PARAMETER Key
    License key to be used
.EXAMPLE
	Remove-VILicenseInfo -Key xxxxx-xxxxx-xxxxx-xxxxx-xxxxx
    Removed the supplied key from the vCenter Server's inventory
.EXAMPLE
	Get-VILicenseInfo -Key xxxxx-xxxxx-xxxxx-xxxxx-xxxxx | Remove-VILicenseInfo
    Removed the supplied key from the vCenter Server's inventory
#>
[CmdletBinding()] 
	param(
		[Parameter(Mandatory=$true,Position=0,ValueFromPipelineByPropertyName=$true)]
        [ValidatePattern(“^\S{5}-\S{5}-\S{5}-\S{5}-\S{5}”)]
		[String]$Key
  	)

	Process {

    if (!$global:DefaultVIServer -or $global:DefaultVIServer.IsConnected -eq $false) {Write-Error "`nNo valid vCenter Server connection found. Please connect to the vCenter Server and try again."}
    else {

        $svcinst = Get-View ServiceInstance
        $licmgr = Get-View $svcinst.Content.LicenseManager

        $licenses = $licmgr.DecodeLicense($Key)
        if (!$licenses.LicenseKey) {Write-Error "`n$key - Valid license not found."}
        else {
	
        if ($licenses.Used -gt "0") {Write-Error "`n$key - License still in use."}
            else{
    
                $licmgr.RemoveLicense($Key)

            }
        }
    }
	} # End of process
} # End of function

function Set-VILicense {
<#  
.SYNOPSIS  
    Sets the supplied license key to the desired VI Object
.DESCRIPTION 
    Will set the provided license key to the desired VI Object
.NOTES  
    Author:  Kyle Ruddy, @kmruddy, thatcouldbeaproblem.com
.PARAMETER Key
    License key to be used
.EXAMPLE
	Set-VILicenseInfo -Key xxxxx-xxxxx-xxxxx-xxxxx-xxxxx -VIObject vcenter.fqdn
    Assigns the supplied key to the supplied VIObject
.EXAMPLE
	Get-VMHost -Name vmhost.fqdn | Set-VILicenseInfo -Key xxxxx-xxxxx-xxxxx-xxxxx-xxxxx
    Assigns the supplied key to the VMHost object received from pipeline
.EXAMPLE
	Get-VILicense -Key xxxxx-xxxxx-xxxxx-xxxxx-xxxxx | Set-VILicenseInfo -VIObject vcenter.fqdn
    Assigns the supplied key received from pipeline to the supplied VIObject
#>
[CmdletBinding()] 
	param(
		[Parameter(Mandatory=$true,Position=0,ValueFromPipelineByPropertyName=$true)]
        [ValidatePattern(“^\S{5}-\S{5}-\S{5}-\S{5}-\S{5}”)]
		[String]$Key,
        [Parameter(Mandatory=$true,Position=1,ValueFromPipelineByPropertyName=$true)]
        [Alias('Name')]
        [String]$VIObject
  	)

	Process {

    if (!$global:DefaultVIServer -or $global:DefaultVIServer.IsConnected -eq $false) {Write-Error "`nNo valid vCenter Server connection found. Please connect to the vCenter Server and try again."}
    else {

        $svcinst = Get-View ServiceInstance
        $licmgr = Get-View $svcinst.Content.LicenseManager
        $licassmgr = Get-View $licmgr.LicenseAssignmentManager

        $licenses = $licmgr.DecodeLicense($Key)
        if (!$licenses.LicenseKey) {Write-Error "`n$key - Valid license not found."}
        else {
	
            if ($licenses.EditionKey -like "vc.*") {
                
                if ($VIObject -like ($global:DefaultVIServer).Name -or $VIObject -like (($global:DefaultVIServer).Name.Split(".")[0])) {
                    
                    $output = $licassmgr.UpdateAssignedLicense($global:DefaultVIServer.InstanceUuid, $Key, $null)
                    
                }

            }

            if ($licenses.EditionKey -like "esx.*") {

                $vmhost = Get-VMHost | ?{$_.Name -like $viobject -or $_.Name.Split(".")[0] -like $viobject}
                if ($vmhost) {$output = $licassmgr.UpdateAssignedLicense($vmhost.ExtensionData.MoRef.Value, $key, $null)}

            }

        }
    }
	} # End of process
} # End of function

function Get-VILicense {
<#  
.SYNOPSIS  
    Gathers information on the supplied license key
.DESCRIPTION 
    Will inventory the provided license key
.NOTES  
    Author:  Kyle Ruddy, @kmruddy, thatcouldbeaproblem.com
.PARAMETER Key
    License key to be used
.EXAMPLE
	Get-VILicense -VIObject vcenter.fqdn
    Displays information about the license key currently assigned to the supplied VIObject
.EXAMPLE
	Get-VMHost -Name vmhost.fqdn | Get-VILicense -VIObject vcenter.fqdn
    Displays information about the license key currently assigned to the received VMHost by pipeline
#>
[CmdletBinding()] 
	param(
        [Parameter(Mandatory=$true,Position=0,ValueFromPipelineByPropertyName=$true)]
        [Alias('Name')]
        [String]$VIObject
  	)

	Process {

    if (!$global:DefaultVIServer -or $global:DefaultVIServer.IsConnected -eq $false) {Write-Error "`nNo valid vCenter Server connection found. Please connect to the vCenter Server and try again."}
    else {

        $svcinst = Get-View ServiceInstance
        $licmgr = Get-View $svcinst.Content.LicenseManager
        $licassmgr = Get-View $licmgr.LicenseAssignmentManager

        if ($VIObject -like ($global:DefaultVIServer).Name -or $VIObject -like (($global:DefaultVIServer).Name.Split(".")[0])) {$uuid = $global:DefaultVIServer.InstanceUuid}
        elseif (Get-VMHost | ?{$_.Name -like $viobject -or $_.Name.Split(".")[0] -like $viobject}) {$uuid = (Get-VMHost | ?{$_.Name -like $viobject -or $_.Name.Split(".")[0] -like $viobject}).ExtensionData.MoRef.Value}

        if (!$uuid) {Write-Error "`n$viobject - VIObject not found."}
        else {

            $key = $licassmgr.QueryAssignedLicenses($uuid).AssignedLicense.LicenseKey

            $licenses = $licmgr.DecodeLicense($key)

            $lreport = @()
	        foreach ($lic in $licenses)
		        {
		        $l = New-Object System.Object
		        $l | Add-Member -Type NoteProperty -Name Name -Value $lic.Name
                $l | Add-Member -Type NoteProperty -Name Version -Value ($lic.Properties | ?{$_.Key -eq "ProductVersion"}).Value
		        $l | Add-Member -Type NoteProperty -Name Key -Value $lic.LicenseKey
		        if (!$lic.Used) {$l | Add-Member -Type NoteProperty -Name Used -Value "0"}
                else {$l | Add-Member -Type NoteProperty -Name Used -Value $lic.Used}
                $l | Add-Member -Type NoteProperty -Name Total -Value $lic.Total
                if ($lic.CostUnit -eq "cpuPackage") {$l | Add-Member -Type NoteProperty -Name Unit -Value "CPUs"}
                elseif ($lic.CostUnit -eq "vm") {$l | Add-Member -Type NoteProperty -Name Unit -Value "VMs"}
                elseif ($lic.CostUnit -eq "server") {$l | Add-Member -Type NoteProperty -Name Unit -Value "Instances"}
                $expire = ($lic.Properties | ?{$_.Key -eq "expirationDate"}).Value
		        if (!$expire) {$l | Add-Member -Type NoteProperty -Name Expiration -Value $null}
                else {$l | Add-Member -Type NoteProperty -Name Expiration -Value (Get-Date $expire -format d)}
        
                $lreport += $l
		        }
	        $lreport | % { $_.PSObject.TypeNames.Insert(0,"VIObject.License") }
	        return $lreport
        }
    
    }
	} # End of process
} # End of function