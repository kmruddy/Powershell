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
	$creport = @()
	foreach ($controller in $rxml.controllers.controller)
		{
		$c = New-Object System.Object
		$c | Add-Member -Type NoteProperty -Name Name -Value $controller.id
		$c | Add-Member -Type NoteProperty -Name IP -Value $controller.ipAddress
		$c | Add-Member -Type NoteProperty -Name Status -Value $controller.status
		$c | Add-Member -Type NoteProperty -Name Version -Value $controller.version
		$c | Add-Member -Type NoteProperty -Name VMName -Value $controller.virtualMachineInfo.name
		$c | Add-Member -Type NoteProperty -Name Host -Value $controller.hostInfo.name
		$c | Add-Member -Type NoteProperty -Name Datastore -Value $controller.datastoreInfo.name
		$creport += $c
		}
	$creport | % { $_.PSObject.TypeNames.Insert(0,"NSX.Controller") }
	return $creport

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
	$ereport = @()
	foreach ($edge in $rxml.pagedEdgeList.edgePage.edgeSummary)
		{
		$e = New-Object System.Object
		$e | Add-Member -Type NoteProperty -Name ID -Value $edge.id
		$e | Add-Member -Type NoteProperty -Name Name -Value $edge.name
		$e | Add-Member -Type NoteProperty -Name Status -Value $edge.edgeStatus
		$e | Add-Member -Type NoteProperty -Name Version -Value $edge.appliancesSummary.vmVersion
		$e | Add-Member -Type NoteProperty -Name State -Value $edge.state
		$e | Add-Member -Type NoteProperty -Name Tenant -Value $edge.tenantId
		$e | Add-Member -Type NoteProperty -Name Size -Value $edge.appliancesSummary.applianceSize
		$ereport += $e
		}
	$ereport | % { $_.PSObject.TypeNames.Insert(0,"NSX.Edges") }
	return $ereport

	} # End of process
} # End of function


function Get-NSXEdgeInterfaces {

<#  
.SYNOPSIS  Gathers NSX Edge Node's Interface details from NSX Manager
.DESCRIPTION Will inventory the selected Edge Node's Interfaces from NSX Manager
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
	$vreport = @()
	foreach ($vnic in $rxml.edge.vnics.vnic)
		{
		$v = New-Object System.Object
		$v | Add-Member -Type NoteProperty -Name Number -Value $vnic.label.Split("_")[1]
		$v | Add-Member -Type NoteProperty -Name Name -Value $vnic.name
		$v | Add-Member -Type NoteProperty -Name IP -Value $vnic.addressGroups.addressGroup.primaryAddress
		$v | Add-Member -Type NoteProperty -Name Prefix -Value $vnic.addressGroups.addressGroup.subnetPrefixLength
		$v | Add-Member -Type NoteProperty -Name ConnectedToPG -Value $vnic.portgroupName
		$v | Add-Member -Type NoteProperty -Name Type -Value $vnic.type
		if ($vnic.isConnected -eq $true) {$v | Add-Member -Type NoteProperty -Name Status -Value "Connected"}
		elseif ($vnic.isConnected -eq $false) {$v | Add-Member -Type NoteProperty -Name Status -Value "Disconnected"}
		else {$v | Add-Member -Type NoteProperty -Name Status -Value "Not Found"}
		$vreport += $v
		}
	$vreport | % { $_.PSObject.TypeNames.Insert(0,"NSX.EInterfaces") }
	$vreport

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
	$ureport = @()
	foreach ($edge in $rxml.pagedEdgeList.edgePage.edgeSummary)
		{
		$Edgeid = $edge.id
				
		### Connect to NSX Manager via API to pull the Edge Node's Uplinks
		$Request = "https://$NSXManager/api/4.0/edges/$Edgeid"
		$r = Invoke-WebRequest -Uri $Request -Headers $head -ContentType "application/xml" -ErrorAction:Stop
		[xml]$rxml = $r.Content
		
		foreach ($vnic in $rxml.edge.vnics.vnic)
			{
			if ($vnic.type -eq "uplink") 
				{
				$u = New-Object System.Object
				$u | Add-Member -Type NoteProperty -Name EdgeID -Value $Edgeid
				$u | Add-Member -Type NoteProperty -Name EdgeName -Value $edge.name
				$u | Add-Member -Type NoteProperty -Name Number -Value $vnic.label.Split("_")[1]
				$u | Add-Member -Type NoteProperty -Name Name -Value $vnic.name
				$u | Add-Member -Type NoteProperty -Name IP -Value $vnic.addressGroups.addressGroup.primaryAddress
				$u | Add-Member -Type NoteProperty -Name Prefix -Value $vnic.addressGroups.addressGroup.subnetPrefixLength
				$u | Add-Member -Type NoteProperty -Name ConnectedToPG -Value $vnic.portgroupName
				$u | Add-Member -Type NoteProperty -Name Type -Value $vnic.type
				$ureport += $u
				}
						
			}
		}
	$ureport | % { $_.PSObject.TypeNames.Insert(0,"NSX.EUplinks") }
	$ureport

	} # End of process
} # End of function

function Get-NSXEdgeNATs {

<#  
.SYNOPSIS  Gathers NSX Edge Node NAT details from NSX Manager
.DESCRIPTION Will inventory all of your Edge Node's NATs from NSX Manager
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
	
	### Return the NSX Edge's NAT Config
	$nreport = @()
	$count = 1
	foreach ($nat in $rxml.nat.natRules.natRule)
		{
		$n = New-Object System.Object
		$n | Add-Member -Type NoteProperty -Name Order -Value $count
		$n | Add-Member -Type NoteProperty -Name ID -Value $nat.ruleId
		$n | Add-Member -Type NoteProperty -Name Type -Value $nat.ruleType
		$n | Add-Member -Type NoteProperty -Name Action -Value $nat.action
		$n | Add-Member -Type NoteProperty -Name OriginalIP -Value $nat.originalAddress
		$n | Add-Member -Type NoteProperty -Name OriginalPort -Value $nat.originalPort
		$n | Add-Member -Type NoteProperty -Name TranslatedIP -Value $nat.translatedAddress
		$n | Add-Member -Type NoteProperty -Name TranslatedPort -Value $nat.translatedPort
		$n | Add-Member -Type NoteProperty -Name Protocol -Value $nat.protocol
		if ($nat.enabled -eq $true) {$n | Add-Member -Type NoteProperty -Name Status -Value "Enabled"}
		elseif ($nat.enabled -eq $false) {$n | Add-Member -Type NoteProperty -Name Status -Value "Not Enabled"}
		else {$n | Add-Member -Type NoteProperty -Name Status -Value "Not Found"}
		$n | Add-Member -Type NoteProperty -Name Logging -Value $nat.loggingEnabled
		if ($nat.description) {$n | Add-Member -Type NoteProperty -Name Description -Value $nat.description}
		else {$n | Add-Member -Type NoteProperty -Name Description -Value $null}
		
		### Connect to NSX Manager via API to pull the Edge Node's Interfaces
		$Request = "https://$NSXManager/api/4.0/edges/$Edgeid"
		$r = Invoke-WebRequest -Uri $Request -Headers $head -ContentType "application/xml" -ErrorAction:Stop
		[xml]$rxml = $r.Content
		
		foreach ($vnic in $rxml.edge.vnics.vnic)
			{
			$number = $vnic.label.Split("_")[1]
			if ($number -eq $nat.vnic) {$n | Add-Member -Type NoteProperty -Name AppliedOn -Value $vnic.name}
			}
				
		$nreport += $n
		$count ++
		}
	$nreport | % { $_.PSObject.TypeNames.Insert(0,"NSX.ENATs") }
	$nreport 

	} # End of process
} # End of function

function Get-NSXEdgeFeatures {

<#  
.SYNOPSIS  Gathers NSX Edge Feature details from all nodes within NSX Manager
.DESCRIPTION Will inventory all of your Edge Nodes' Features from NSX Manager
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
	PS> Get-NSXEdgeFeatures -NSXManager nsxmgr.fqdn -Username admin -Password password
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
	
	### Return the NSX Edges
	$freport = @()
	foreach ($edge in $rxml.pagedEdgeList.edgePage.edgeSummary)
		{
		$Edgeid = $edge.id
				
		### Connect to NSX Manager via API to pull the Edge Node's Features
		$Request = "https://$NSXManager/api/4.0/edges/$Edgeid"
		$r = Invoke-WebRequest -Uri $Request -Headers $head -ContentType "application/xml" -ErrorAction:Stop
		[xml]$rxml = $r.Content
		
		foreach ($feature in $rxml.edge.features)
				{
				$f = New-Object System.Object
				$f | Add-Member -Type NoteProperty -Name EdgeID -Value $Edgeid
				$f | Add-Member -Type NoteProperty -Name EdgeName -Value $edge.name
				$f | Add-Member -Type NoteProperty -Name LoadBalancer -Value $feature.loadBalancer.enabled
				$f | Add-Member -Type NoteProperty -Name Routing -Value $feature.routing.enabled
				$f | Add-Member -Type NoteProperty -Name IPsecVPN -Value $feature.ipsec.enabled
				$f | Add-Member -Type NoteProperty -Name L2VPN -Value $feature.l2Vpn.enabled
				$f | Add-Member -Type NoteProperty -Name Syslog -Value $feature.syslog.enabled
				$f | Add-Member -Type NoteProperty -Name Firewall -Value $feature.firewall.enabled
				$f | Add-Member -Type NoteProperty -Name DHCP -Value $feature.dhcp.enabled
				$f | Add-Member -Type NoteProperty -Name DNS -Value $feature.dns.enabled
				$f | Add-Member -Type NoteProperty -Name HA -Value $feature.highAvailability.enabled
				$f | Add-Member -Type NoteProperty -Name NAT -Value $feature.nat.enabled
				$f | Add-Member -Type NoteProperty -Name SSLVPN -Value $feature.sslvpnConfig.enabled
				$freport += $f
				}
		}
	$freport | % { $_.PSObject.TypeNames.Insert(0,"NSX.EFeatures") }
	$freport

	} # End of process
} # End of function

function Get-NSXEdgeRoutingOverview {

<#  
.SYNOPSIS  Gathers NSX Edge Routing Overview details from all nodes within NSX Manager
.DESCRIPTION Will inventory all of your Edge Nodes' Routing Overview details from NSX Manager
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
	PS> Get-NSXEdgeRoutingOverview -NSXManager nsxmgr.fqdn -Username admin -Password password
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
	$roreport = @()
	foreach ($edge in $rxml.pagedEdgeList.edgePage.edgeSummary)
		{
		$Edgeid = $edge.id
				
		### Connect to NSX Manager via API to pull the Edge Nodes' Routing Config
		$Request = "https://$NSXManager/api/4.0/edges/$Edgeid/routing/config"
		$r = Invoke-WebRequest -Uri $Request -Headers $head -ContentType "application/xml" -ErrorAction:Stop
		[xml]$rxml = $r.Content
		
		foreach ($routing in $rxml.routing)
				{
				$ro = New-Object System.Object
				$ro | Add-Member -Type NoteProperty -Name EdgeID -Value $Edgeid
				$ro | Add-Member -Type NoteProperty -Name EdgeName -Value $edge.name
				$ro | Add-Member -Type NoteProperty -Name Status -Value $routing.enabled
				$ro | Add-Member -Type NoteProperty -Name ECMP -Value $routing.routingGlobalConfig.ecmp
				
				### Connect to NSX Manager via API to pull the Edge Node's Interfaces
				$Request = "https://$NSXManager/api/4.0/edges/$Edgeid"
				$r = Invoke-WebRequest -Uri $Request -Headers $head -ContentType "application/xml" -ErrorAction:Stop
				[xml]$rxml = $r.Content
				
				foreach ($vnic in $rxml.edge.vnics.vnic)
					{
					$number = $vnic.label.Split("_")[1]
					if ($number -eq $routing.staticRouting.defaultRoute.vnic) {$ro | Add-Member -Type NoteProperty -Name GWvNIC -Value $vnic.name}
					}
				
				$ro | Add-Member -Type NoteProperty -Name GWIP -Value $routing.staticRouting.defaultRoute.gatewayAddress
				$ro | Add-Member -Type NoteProperty -Name GWMTU -Value $routing.staticRouting.defaultRoute.mtu
				if ($routing.staticRouting.defaultRoute.description) {$ro | Add-Member -Type NoteProperty -Name GWDescription -Value $routing.staticRouting.defaultRoute.description}
				else {$ro | Add-Member -Type NoteProperty -Name GWDescription -Value ""}
				$ro | Add-Member -Type NoteProperty -Name RouterID -Value $routing.routingGlobalConfig.routerId
				if ($routing.ospf.enabled) {$ro | Add-Member -Type NoteProperty -Name OSPF -Value $routing.ospf.enabled}
				else {$ro | Add-Member -Type NoteProperty -Name OSPF -Value $false}
				if ($routing.bgp.enabled) {$ro | Add-Member -Type NoteProperty -Name BGP -Value $routing.bgp.enabled}
				else {$ro | Add-Member -Type NoteProperty -Name BGP -Value $false}
				if ($routing.isis.enabled) {$ro | Add-Member -Type NoteProperty -Name ISIS -Value $routing.isis.enabled}
				else {$ro | Add-Member -Type NoteProperty -Name ISIS -Value $false}
				$ro | Add-Member -Type NoteProperty -Name Logging -Value $routing.routingGlobalConfig.logging.enable
				if ($routing.routingGlobalConfig.logging.enable -eq $true) {$ro | Add-Member -Type NoteProperty -Name LogLevel -Value $routing.routingGlobalConfig.logging.logLevel}
				else {$ro | Add-Member -Type NoteProperty -Name LogLevel -Value ""}
				$roreport += $ro
				}
		}
	$roreport | % { $_.PSObject.TypeNames.Insert(0,"NSX.ERoutingOverview") }
	$roreport

	} # End of process
} # End of function
