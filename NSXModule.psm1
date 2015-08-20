function Get-NSXController {

<#  
.SYNOPSIS  Gathers NSX Controller details from NSX Manager
.DESCRIPTION Will inventory all of your controllers from NSX Manager
.NOTES  Author:  Chris Wahl, @ChrisWahl, WahlNetwork.com
.PARAMETER NSXManager
	The FQDN or IP of your NSX Manager
.PARAMETER Username
	The username to connect with. Defaults to admin if nothing is provided.
.PARAMETER Password
	The password to connect with
.EXAMPLE
	PS> Get-NSXController -NSXManager nsxmgr.fqdn -Username admin -Password password
#>

[CmdletBinding()] 
	param(
		[Parameter(Mandatory=$true,Position=0)]
		[String]$NSXManager,
		[Parameter(Mandatory=$false,Position=1)]
		[String]$Username = "admin",
		[Parameter(Mandatory=$true)]
		[String]$Password
  	)

	Process {

	if (!("trustallcertspolicy" -as [type])) {
	### Ignore TLS/SSL errors	
	add-type @"
	    using System.Net;
	    using System.Security.Cryptography.X509Certificates;
	    public class TrustAllCertsPolicy : ICertificatePolicy {
	        public bool CheckValidationResult(
	            ServicePoint srvPoint, X509Certificate certificate,
	            WebRequest request, int certificateProblem) {
	            return true;
	        }
	    }
"@
	[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
	}

	### Create authorization string and store in $head
	$auth = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Username + ":" + $Password))
	$head = @{"Authorization"="Basic $auth"}

	### Connect to NSX Manager via API
	$Request = "https://$NSXManager/api/2.0/vdn/controller"
	$r = Invoke-WebRequest -Uri $Request -Headers $head -ContentType "application/xml" -ErrorAction:Stop
	if ($r.StatusCode -eq "200") {Write-Host -BackgroundColor:Black -ForegroundColor:Green Status: Connected to $NSXManager successfully.}
	[xml]$rxml = $r.Content
	
	### Return the NSX Controllers
	$global:nreport = @()
	foreach ($controller in $rxml.controllers.controller)
		{
		$n = @{} | select Name,IP,Status,Version,VMName,Host,Datastore
		$n.Name = $controller.id
		$n.IP = $controller.ipAddress
		$n.Status = $controller.status
		$n.Version = $controller.version
		$n.VMName = $controller.virtualMachineInfo.name
		$n.Host = $controller.hostInfo.name
		$n.Datastore = $controller.datastoreInfo.name
		$global:nreport += $n
		}
	$global:nreport | ft -AutoSize

	} # End of process
} # End of function

function Get-NSXEdges {

<#  
.SYNOPSIS  Gathers NSX Edge Node details from NSX Manager
.DESCRIPTION Will inventory all of your Edge Nodes from NSX Manager
.NOTES  Author:  Kyle Ruddy, @RuddyVCP, thatcouldbeaproblem.com, thatcouldbeaproblem.com
	Binding, SSL and Authentication sections sourced from Chris Wahl's github repo: https://github.com/WahlNetwork/powershell-scripts/blob/master/VMware%20NSX/Get-NSXController.ps1
.PARAMETER NSXManager
	The FQDN or IP of your NSX Manager
.PARAMETER Username
	The username to connect with. Defaults to admin if nothing is provided.
.PARAMETER Password
	The password to connect with
.EXAMPLE
	PS> Get-NSXEdges -NSXManager nsxmgr.fqdn -Username admin -Password password
#>

[CmdletBinding()] 
	param(
		[Parameter(Mandatory=$true,Position=0)]
		[String]$NSXManager,
		[Parameter(Mandatory=$false,Position=1)]
		[String]$Username = "admin",
		[Parameter(Mandatory=$true)]
		[String]$Password
  	)

	Process {

	if (!("trustallcertspolicy" -as [type])) {
	### Ignore TLS/SSL errors	
	add-type @"
	    using System.Net;
	    using System.Security.Cryptography.X509Certificates;
	    public class TrustAllCertsPolicy : ICertificatePolicy {
	        public bool CheckValidationResult(
	            ServicePoint srvPoint, X509Certificate certificate,
	            WebRequest request, int certificateProblem) {
	            return true;
	        }
	    }
"@
	[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
	}

	### Create authorization string and store in $head
	$auth = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Username + ":" + $Password))
	$head = @{"Authorization"="Basic $auth"}

	### Connect to NSX Manager via API
	$Request = "https://$NSXManager/api/4.0/edges/"
	$r = Invoke-WebRequest -Uri $Request -Headers $head -ContentType "application/xml" -ErrorAction:Stop
	if ($r.StatusCode -eq "200") {Write-Host -BackgroundColor:Black -ForegroundColor:Green Status: Connected to $NSXManager successfully.}
	[xml]$rxml = $r.Content
	
	### Return the NSX Edge Nodes
	$global:nreport = @()
	foreach ($edge in $rxml.pagedEdgeList.edgePage.edgeSummary)
		{
		$e = @{} | select ID,Name,Status,Version,State,Tenant,Size
		$e.ID = $edge.id
		$e.Name = $edge.name
		$e.Status = $edge.edgeStatus
		$e.Version = $edge.appliancesSummary.vmVersion
		$e.State = $edge.state
		$e.Tenant = $edge.tenantId
		$e.Size = $edge.appliancesSummary.applianceSize
		$global:nreport += $e
		}
	$global:nreport | ft -AutoSize

	} # End of process
} # End of function


function Get-NSXEdgeInterfaces {

<#  
.SYNOPSIS  Gathers NSX Edge Node's Interface details from NSX Manager
.DESCRIPTION Will inventory all of your Edge Node's Interfaces from NSX Manager
.NOTES  Author:  Kyle Ruddy, @RuddyVCP, thatcouldbeaproblem.com
	Binding, SSL and Authentication sections sourced from Chris Wahl's github repo: https://github.com/WahlNetwork/powershell-scripts/blob/master/VMware%20NSX/Get-NSXController.ps1
.PARAMETER NSXManager
	The FQDN or IP of your NSX Manager
.PARAMETER Username
	The username to connect with. Defaults to admin if nothing is provided.
.PARAMETER Password
	The password to connect with
.PARAMETER EdgeID
	The Edge Node ID to pull information from
.EXAMPLE
	PS> Get-NSXEdgeInterfaces -NSXManager nsxmgr.fqdn -Username admin -Password password -EdgeID edge-1
#>

[CmdletBinding()] 
	param(
		[Parameter(Mandatory=$true,Position=0)]
		[String]$NSXManager,
		[Parameter(Mandatory=$false,Position=1)]
		[String]$Username = "admin",
		[Parameter(Mandatory=$true,Position=2)]
		[String]$Password,
		[Parameter(Mandatory=$true)]
		[String]$Edgeid
  	)

	Process {

	if (!("trustallcertspolicy" -as [type])) {
	### Ignore TLS/SSL errors	
	add-type @"
	    using System.Net;
	    using System.Security.Cryptography.X509Certificates;
	    public class TrustAllCertsPolicy : ICertificatePolicy {
	        public bool CheckValidationResult(
	            ServicePoint srvPoint, X509Certificate certificate,
	            WebRequest request, int certificateProblem) {
	            return true;
	        }
	    }
"@
	[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
	}

	### Create authorization string and store in $head
	$auth = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Username + ":" + $Password))
	$head = @{"Authorization"="Basic $auth"}

	### Connect to NSX Manager via API
	$Request = "https://$NSXManager/api/4.0/edges/$Edgeid"
	$r = Invoke-WebRequest -Uri $Request -Headers $head -ContentType "application/xml" -ErrorAction:Stop
	if ($r.StatusCode -eq "200") {Write-Host -BackgroundColor:Black -ForegroundColor:Green Status: Connected to $NSXManager successfully.}
	[xml]$rxml = $r.Content
	
	### Return the NSX Edge Node's Interfaces
	$global:nreport = @()
	foreach ($vnic in $rxml.edge.vnics.vnic)
		{
		$v = @{} | select Number,Name,IP,Prefix,ConnectedToPG,Type,Status
		$v.Number = $vnic.label.Split("_")[1]
		$v.Name = $vnic.name
		$v.IP = $vnic.addressGroups.addressGroup.primaryAddress
		$v.Prefix = $vnic.addressGroups.addressGroup.subnetPrefixLength
		$v.ConnectedToPG = $vnic.portgroupName
		$v.Type = $vnic.type
		if ($vnic.isConnected -eq $true) {$v.Status = "Connected"}
		elseif ($vnic.isConnected -eq $false) {$v.Status = "Disconnected"}
		else {$v.Status = "Not Found"}
		$global:nreport += $v
		}
	$global:nreport | ft -AutoSize

	} # End of process
} # End of function

function Get-NSXEdgeUplinks {

<#  
.SYNOPSIS  Gathers NSX Edge Uplink details from all nodes within NSX Manager
.DESCRIPTION Will inventory all of your Edge Nodes' Uplinks from NSX Manager
.NOTES  Author:  Kyle Ruddy, @RuddyVCP, thatcouldbeaproblem.com
	Binding, SSL and Authentication sections sourced from Chris Wahl's github repo: https://github.com/WahlNetwork/powershell-scripts/blob/master/VMware%20NSX/Get-NSXController.ps1
.PARAMETER NSXManager
	The FQDN or IP of your NSX Manager
.PARAMETER Username
	The username to connect with. Defaults to admin if nothing is provided.
.PARAMETER Password
	The password to connect with
.PARAMETER EdgeID
	The Edge Node ID to pull information from
.EXAMPLE
	PS> Get-NSXEdgeUplinks -NSXManager nsxmgr.fqdn -Username admin -Password password
#>

[CmdletBinding()] 
	param(
		[Parameter(Mandatory=$true,Position=0)]
		[String]$NSXManager,
		[Parameter(Mandatory=$false,Position=1)]
		[String]$Username = "admin",
		[Parameter(Mandatory=$true)]
		[String]$Password
  	)

	Process {

	if (!("trustallcertspolicy" -as [type])) {
	### Ignore TLS/SSL errors	
	add-type @"
	    using System.Net;
	    using System.Security.Cryptography.X509Certificates;
	    public class TrustAllCertsPolicy : ICertificatePolicy {
	        public bool CheckValidationResult(
	            ServicePoint srvPoint, X509Certificate certificate,
	            WebRequest request, int certificateProblem) {
	            return true;
	        }
	    }
"@
	[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
	}

	### Create authorization string and store in $head
	$auth = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Username + ":" + $Password))
	$head = @{"Authorization"="Basic $auth"}

	### Connect to NSX Manager via API
	$Request = "https://$NSXManager/api/4.0/edges/"
	$r = Invoke-WebRequest -Uri $Request -Headers $head -ContentType "application/xml" -ErrorAction:Stop
	if ($r.StatusCode -eq "200") {Write-Host -BackgroundColor:Black -ForegroundColor:Green Status: Connected to $NSXManager successfully.}
	[xml]$rxml = $r.Content
	
	### Return the NSX Edge Nodes' Uplinks
	$global:nreport = @()
	foreach ($edge in $rxml.pagedEdgeList.edgePage.edgeSummary)
		{
		$u = @{} | select EdgeID,EdgeName,Number,Name,IP,Prefix,ConnectedToPG,Type
		$Edgeid = $edge.id
		$u.EdgeID = $Edgeid
		$u.EdgeName = $edge.name
		
		### Connect to NSX Manager via API to pull the Edge Node's Uplinks
		$Request = "https://$NSXManager/api/4.0/edges/$Edgeid"
		$r = Invoke-WebRequest -Uri $Request -Headers $head -ContentType "application/xml" -ErrorAction:Stop
		[xml]$rxml = $r.Content
		
		foreach ($vnic in $rxml.edge.vnics.vnic)
			{
			if ($vnic.type -eq "uplink") 
				{
				$u.Number = $vnic.label.Split("_")[1]
				$u.Name = $vnic.name
				$u.IP = $vnic.addressGroups.addressGroup.primaryAddress
				$u.Prefix = $vnic.addressGroups.addressGroup.subnetPrefixLength
				$u.ConnectedToPG = $vnic.portgroupName
				$u.Type = $vnic.type
				$global:nreport += $u
				}
						
			}
		}
	$global:nreport | ft -AutoSize

	} # End of process
} # End of function

function Get-NSXEdgeNATs {

<#  
.SYNOPSIS  Gathers NSX Edge Node NAT details from NSX Manager
.DESCRIPTION Will inventory all of your Edge Node NATs from NSX Manager
.NOTES  Author:  Kyle Ruddy, @RuddyVCP, thatcouldbeaproblem.com
	Binding, SSL and Authentication sections sourced from Chris Wahl's github repo: https://github.com/WahlNetwork/powershell-scripts/blob/master/VMware%20NSX/Get-NSXController.ps1
.PARAMETER NSXManager
	The FQDN or IP of your NSX Manager
.PARAMETER Username
	The username to connect with. Defaults to admin if nothing is provided.
.PARAMETER Password
	The password to connect with
.PARAMETER EdgeID
	The Edge Node ID to pull information from
.EXAMPLE
	PS> Get-NSXEdgeNATs -NSXManager nsxmgr.fqdn -Username admin -Password password -EdgeID edge-1
#>

[CmdletBinding()] 
	param(
		[Parameter(Mandatory=$true,Position=0)]
		[String]$NSXManager,
		[Parameter(Mandatory=$false,Position=1)]
		[String]$Username = "admin",
		[Parameter(Mandatory=$true,Position=2)]
		[String]$Password,
		[Parameter(Mandatory=$true)]
		[String]$Edgeid
  	)

	Process {

	if (!("trustallcertspolicy" -as [type])) {
	### Ignore TLS/SSL errors	
	add-type @"
	    using System.Net;
	    using System.Security.Cryptography.X509Certificates;
	    public class TrustAllCertsPolicy : ICertificatePolicy {
	        public bool CheckValidationResult(
	            ServicePoint srvPoint, X509Certificate certificate,
	            WebRequest request, int certificateProblem) {
	            return true;
	        }
	    }
"@
	[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
	}

	### Create authorization string and store in $head
	$auth = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Username + ":" + $Password))
	$head = @{"Authorization"="Basic $auth"}

	### Connect to NSX Manager via API
	$Request = "https://$NSXManager/api/4.0/edges/$Edgeid/nat/config"
	$r = Invoke-WebRequest -Uri $Request -Headers $head -ContentType "application/xml" -ErrorAction:Stop
	if ($r.StatusCode -eq "200") {Write-Host -BackgroundColor:Black -ForegroundColor:Green Status: Connected to $NSXManager successfully.}
	[xml]$rxml = $r.Content
	
	### Return the NSX Controllers
	$global:nreport = @()
	$count = 1
	foreach ($nat in $rxml.nat.natRules.natRule)
		{
		$n = @{} | select Order,ID,Type,Action,AppliedOn,OriginalIP,OriginalPort,TranslatedIP,TranslatedPort,Protocol,Status,Logging,Description
		$n.Order = $count
		$n.ID = $nat.ruleId
		$n.Type = $nat.ruleType
		$n.Action = $nat.action
		$n.OriginalIP = $nat.originalAddress
		$n.OriginalPort = $nat.originalPort
		$n.TranslatedIP = $nat.translatedAddress
		$n.TranslatedPort = $nat.translatedPort
		$n.Protocol = $nat.protocol
		if ($nat.enabled -eq $true) {$n.Status = "Enabled"}
		elseif ($nat.enabled -eq $false) {$n.Status = "Not Enabled"}
		else {$n.Status = "Not Found"}
		$n.Logging = $nat.loggingEnabled
		if ($nat.description) {$n.Description}
		else {$n.Description = $null}
		
		### Connect to NSX Manager via API to pull the Edge Node's Interfaces
		$Request = "https://$NSXManager/api/4.0/edges/$Edgeid"
		$r = Invoke-WebRequest -Uri $Request -Headers $head -ContentType "application/xml" -ErrorAction:Stop
		[xml]$rxml = $r.Content
		
		foreach ($vnic in $rxml.edge.vnics.vnic)
			{
			$number = $vnic.label.Split("_")[1]
			if ($number -eq $nat.vnic) {$n.AppliedOn = $vnic.name}
			}
				
		$global:nreport += $n
		$count ++
		}
	$global:nreport | ft -autosize

	} # End of process
} # End of function
