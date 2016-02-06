function Get-NSXController {
<#  
.SYNOPSIS  
    Gathers NSX Controller details from NSX Manager

.DESCRIPTION 
    Will inventory all of your controllers from NSX Manager

.NOTES  
    Author:  Chris Wahl, @ChrisWahl, WahlNetwork.com

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
	$r = Invoke-RestMethod -Uri $Request -Headers $head -ContentType "application/xml" -ErrorAction:Stop
		
	### Return the NSX Controllers
	$creport = @()
	foreach ($controller in $r.controllers.controller)
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
.SYNOPSIS  
    Gathers NSX Edge Node details from NSX Manager

.DESCRIPTION 
    Will inventory all of your Edge Nodes from NSX Manager

.NOTES  
    Author:  Kyle Ruddy, @kmruddy, thatcouldbeaproblem.com
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
	$r = Invoke-RestMethod -Uri $Request -Headers $head -ContentType "application/xml" -ErrorAction:Stop
	
	### Return the NSX Edge Nodes
	$ereport = @()
	foreach ($edge in $r.pagedEdgeList.edgePage.edgeSummary)
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
.SYNOPSIS  
    Gathers NSX Edge Node's Interface details from NSX Manager

.DESCRIPTION 
    Will inventory the selected Edge Node's Interfaces from NSX Manager

.NOTES  
    Author:  Kyle Ruddy, @kmruddy, thatcouldbeaproblem.com
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
	$r = Invoke-RestMethod -Uri $Request -Headers $head -ContentType "application/xml" -ErrorAction:Stop
	
	### Return the NSX Edge Node's Interfaces
	$vreport = @()
	foreach ($vnic in $r.edge.vnics.vnic)
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
.SYNOPSIS  
    Gathers NSX Edge Uplink details from all nodes within NSX Manager
.DESCRIPTION 
    Will inventory all of your Edge Nodes' Uplinks from NSX Manager
.NOTES  
    Author:  Kyle Ruddy, @kmruddy, thatcouldbeaproblem.com
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
	$r = Invoke-RestMethod -Uri $Request -Headers $head -ContentType "application/xml" -ErrorAction:Stop
	
	### Return the NSX Edge Nodes' Uplinks
	$ureport = @()
	foreach ($edge in $r.pagedEdgeList.edgePage.edgeSummary)
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
.SYNOPSIS  
    Gathers NSX Edge Node NAT details from NSX Manager

.DESCRIPTION 
    Will inventory all of your Edge Node's NATs from NSX Manager

.NOTES  
    Author:  Kyle Ruddy, @kmruddy, thatcouldbeaproblem.com
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
	$r = Invoke-RestMethod -Uri $Request -Headers $head -ContentType "application/xml" -ErrorAction:Stop
	
	### Return the NSX Edge's NAT Config
	$nreport = @()
	$count = 1
	foreach ($nat in $r.nat.natRules.natRule)
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

.SYNOPSIS  
    Gathers NSX Edge Feature details from all nodes within NSX Manager

.DESCRIPTION 
    Will inventory all of your Edge Nodes' Features from NSX Manager

.NOTES  
    Author:  Kyle Ruddy, @kmruddy, thatcouldbeaproblem.com
	Binding, SSL and Authentication sections sourced from Chris Wahl's github repo: https://github.com/WahlNetwork/powershell-scripts/blob/master/VMware%20NSX/Get-NSXController.ps1

.PARAMETER NSXManager
	The FQDN or IP of your NSX Manager

.PARAMETER Username
	The username to connect with. Defaults to admin if nothing is provided.

.PARAMETER Password
	The password to connect with

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
	$r = Invoke-RestMethod -Uri $Request -Headers $head -ContentType "application/xml" -ErrorAction:Stop
	
	### Return the NSX Edges
	$freport = @()
	foreach ($edge in $r.pagedEdgeList.edgePage.edgeSummary)
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
.SYNOPSIS  
    Gathers NSX Edge Routing Overview details from all nodes within NSX Manager

.DESCRIPTION 
    Will inventory all of your Edge Nodes' Routing Overview details from NSX Manager

.NOTES  
    Author:  Kyle Ruddy, @kmruddy, thatcouldbeaproblem.com
	Binding, SSL and Authentication sections sourced from Chris Wahl's github repo: https://github.com/WahlNetwork/powershell-scripts/blob/master/VMware%20NSX/Get-NSXController.ps1

.PARAMETER NSXManager
	The FQDN or IP of your NSX Manager

.PARAMETER Username
	The username to connect with. Defaults to admin if nothing is provided.

.PARAMETER Password
	The password to connect with

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
	$r = Invoke-RestMethod -Uri $Request -Headers $head -ContentType "application/xml" -ErrorAction:Stop
	
	### Return the NSX Edge Nodes
	$roreport = @()
	foreach ($edge in $r.pagedEdgeList.edgePage.edgeSummary)
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

function Get-NSXControllerUpgrade {
<#  
.SYNOPSIS  
    Gathers NSX Controller Upgrade details from NSX Manager

.DESCRIPTION 
    Will inventory all of your controllers upgrade availability from NSX Manager
.NOTES  
    Author:  Kyle Ruddy, @kmruddy, thatcouldbeaproblem.com
	Binding, SSL and Authentication sections sourced from Chris Wahl's github repo: https://github.com/WahlNetwork/powershell-scripts/blob/master/VMware%20NSX/Get-NSXController.ps1

.PARAMETER NSXManager
	The FQDN or IP of your NSX Manager

.PARAMETER Username
	The username to connect with. Defaults to admin if nothing is provided.

.PARAMETER Password
	The password to connect with

.EXAMPLE
	PS> Get-NSXControllerUpgrade -NSXManager nsxmgr.fqdn -Username admin -Password password
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
	$r = Invoke-RestMethod -Uri $Request -Headers $head -ContentType "application/xml" -ErrorAction:Stop

    $Request = "https://$NSXManager/api/2.0/vdn/controller/upgrade-available"
    $u = Invoke-RestMethod -Uri $Request -Headers $head -contenttype "application/xml" -ErrorAction:Stop -Method Get
	
	### Return the NSX Controllers
	$creport = @()
	foreach ($controller in $r.controllers.controller)
		{
		$c = New-Object System.Object
		$c | Add-Member -Type NoteProperty -Name Name -Value $controller.id
		$c | Add-Member -Type NoteProperty -Name IP -Value $controller.ipAddress
		$c | Add-Member -Type NoteProperty -Name Status -Value $controller.status
		$c | Add-Member -Type NoteProperty -Name Version -Value $controller.version
		$c | Add-Member -Type NoteProperty -Name UpgradeAvailable -Value $u.controllerClusterUpgradeAvailability.upgradeAvailable
		$creport += $c
		}
	$creport | % { $_.PSObject.TypeNames.Insert(0,"NSX.ControllerUpgrade") }
	return $creport

	} # End of process
} # End of function

function Get-NSXManager {
<#  

.SYNOPSIS  
    Gathers NSX Manager details

.DESCRIPTION 
    Will inventory information from NSX Manager

.NOTES  
    Author:  Kyle Ruddy, @kmruddy, thatcouldbeaproblem.com
	Binding, SSL and Authentication sections sourced from Chris Wahl's github repo: https://github.com/WahlNetwork/powershell-scripts/blob/master/VMware%20NSX/Get-NSXController.ps1

.PARAMETER NSXManager
	The FQDN or IP of your NSX Manager

.PARAMETER Username
	The username to connect with. Defaults to admin if nothing is provided.

.PARAMETER Password
	The password to connect with

.EXAMPLE
	PS> Get-NSXManager -NSXManager nsxmgr.fqdn -Username admin -Password password
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
	$Request = "https://$NSXManager/api/1.0/appliance-management/summary/system"
	$r = Invoke-RestMethod -Uri $Request -Headers $head -contenttype "application/xml" -ErrorAction:Stop -Method Get
	
	### Return the NSX Manager Info
	$mreport = New-Object System.Object
	$mreport | Add-Member -Type NoteProperty -Name Name -Value $r.hostName
	$mreport | Add-Member -Type NoteProperty -Name IP -Value $r.ipv4Address
	$mreport | Add-Member -Type NoteProperty -Name Version -Value ($r.versionInfo.majorVersion + "." + $r.versionInfo.minorVersion + "." + $r.versionInfo.patchVersion)
    $mreport | Add-Member -Type NoteProperty -Name Build -Value $r.versionInfo.buildNumber
	$mreport | Add-Member -Type NoteProperty -Name Uptime -Value $r.uptime
	$mreport | % { $_.PSObject.TypeNames.Insert(0,"NSX.Manager") }
	return $mreport

	} # End of process
} # End of function

function Restart-NSXManager {
<#  
.SYNOPSIS  
    Configures the NSX Manager for reboot

.DESCRIPTION 
    Reboots the NSX Manager

.NOTES  
    Author:  Kyle Ruddy, @kmruddy, thatcouldbeaproblem.com
	Binding, SSL and Authentication sections sourced from Chris Wahl's github repo: https://github.com/WahlNetwork/powershell-scripts/blob/master/VMware%20NSX/Get-NSXController.ps1

.PARAMETER NSXManager
	The FQDN or IP of your NSX Manager

.PARAMETER Username
	The username to connect with. Defaults to admin if nothing is provided.

.PARAMETER Password
	The password to connect with

.PARAMETER Restart
	A True/False option to confirm the desire to restart the NSX Manager

.EXAMPLE
	PS> Restart-NSXManager -NSXManager nsxmgr.fqdn -Username admin -Password password -Restart $true
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
		[Boolean]$Restart = $false
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

    if ($Restart -eq $true) {

	### Connect to NSX Manager via API
	$Request = "https://$NSXManager/api/1.0/appliance-management/system/restart"
	$r = Invoke-RestMethod -Uri $Request -Headers $head -contenttype "application/xml" -ErrorAction:Stop -Method Post
	
    }

	} # End of process
} # End of function

function Get-NSXManagerComponents {
<#  
.SYNOPSIS  
    Gathers NSX Manager component details

.DESCRIPTION 
    Will inventory component information from NSX Manager

.NOTES  
    Author:  Kyle Ruddy, @kmruddy, thatcouldbeaproblem.com
	Binding, SSL and Authentication sections sourced from Chris Wahl's github repo: https://github.com/WahlNetwork/powershell-scripts/blob/master/VMware%20NSX/Get-NSXController.ps1

.PARAMETER NSXManager
	The FQDN or IP of your NSX Manager

.PARAMETER Username
	The username to connect with. Defaults to admin if nothing is provided.

.PARAMETER Password
	The password to connect with

.EXAMPLE
	PS> Get-NSXManagerComponents -NSXManager nsxmgr.fqdn -Username admin -Password password
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
	$Request = "https://$NSXManager/api/1.0/appliance-management/components"
	$r = Invoke-RestMethod -Uri $Request -Headers $head -contenttype "application/xml" -ErrorAction:Stop -Method Get
	
	### Return the NSX Manager Info
    $creport = @()
    foreach ($comp in $r.Components) {
    $c = New-Object System.Object
    $c | Add-Member -Type NoteProperty -Name ID -Value $comp.componentId
	$c | Add-Member -Type NoteProperty -Name Name -Value $comp.Name
	$c | Add-Member -Type NoteProperty -Name Description -Value $comp.Description
    $c | Add-Member -Type NoteProperty -Name Status -Value $comp.status
    $c | Add-Member -Type NoteProperty -Name Enabled -Value $comp.enabled
    $c | Add-Member -Type NoteProperty -Name ShowLogs -Value $comp.showTechSupportLogs
    if ($comp.uses) {$c | Add-Member -Type NoteProperty -Name Uses -Value ($comp.uses -join ", ")} 
    else {$c | Add-Member -Type NoteProperty -Name Uses -Value $null}
    if ($comp.usedBy) {$c | Add-Member -Type NoteProperty -Name UsedBy -Value ($comp.usedBy -join ", ")} 
    else {$c | Add-Member -Type NoteProperty -Name UsedBy -Value $null}
    $c | Add-Member -Type NoteProperty -Name ComponentGroup -Value $comp.componentGroup
    if ($comp.versionInfo) {$c | Add-Member -Type NoteProperty -Name Version -Value ($comp.versionInfo.majorVersion + "." + $comp.versionInfo.minorVersion + "." + $comp.versionInfo.patchVersion + " Build " + $comp.versionInfo.buildNumber)} 
    else {$c | Add-Member -Type NoteProperty -Name Version -Value $null}
	$creport += $c
    }
    $creport | % { $_.PSObject.TypeNames.Insert(0,"NSX.ManagerComponents") }
	return $creport

	} # End of process
} # End of function

function Get-NSXManagerSSH {
<#  
.SYNOPSIS  
    Gathers NSX Manager SSH component details

.DESCRIPTION 
    Will inventory SSH component information from NSX Manager

.NOTES  
    Author:  Kyle Ruddy, @kmruddy, thatcouldbeaproblem.com
	Binding, SSL and Authentication sections sourced from Chris Wahl's github repo: https://github.com/WahlNetwork/powershell-scripts/blob/master/VMware%20NSX/Get-NSXController.ps1

.PARAMETER NSXManager
	The FQDN or IP of your NSX Manager

.PARAMETER Username
	The username to connect with. Defaults to admin if nothing is provided.

.PARAMETER Password
	The password to connect with

.EXAMPLE
	PS> Get-NSXManagerSSH -NSXManager nsxmgr.fqdn -Username admin -Password password
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
	$Request = "https://$NSXManager/api/1.0/appliance-management/components/component/SSH"
	$r = Invoke-RestMethod -Uri $Request -Headers $head -contenttype "application/xml" -ErrorAction:Stop -Method Get
	
	### Return the NSX Manager Info
    $creport = @()
    foreach ($comp in $r) {
    $c = New-Object System.Object
    $c | Add-Member -Type NoteProperty -Name ID -Value $comp.componentId
	$c | Add-Member -Type NoteProperty -Name Name -Value $comp.Name
	$c | Add-Member -Type NoteProperty -Name Description -Value $comp.Description
    $c | Add-Member -Type NoteProperty -Name Status -Value $comp.status
    $c | Add-Member -Type NoteProperty -Name Enabled -Value $comp.enabled
    $c | Add-Member -Type NoteProperty -Name ShowLogs -Value $comp.showTechSupportLogs
    if ($comp.uses) {$c | Add-Member -Type NoteProperty -Name Uses -Value ($comp.uses -join ", ")} 
    else {$c | Add-Member -Type NoteProperty -Name Uses -Value $null}
    if ($comp.usedBy) {$c | Add-Member -Type NoteProperty -Name UsedBy -Value ($comp.usedBy -join ", ")} 
    else {$c | Add-Member -Type NoteProperty -Name UsedBy -Value $null}
    $c | Add-Member -Type NoteProperty -Name ComponentGroup -Value $comp.componentGroup
    if ($comp.versionInfo) {$c | Add-Member -Type NoteProperty -Name Version -Value ($comp.versionInfo.majorVersion + "." + $comp.versionInfo.minorVersion + "." + $comp.versionInfo.patchVersion + " Build " + $comp.versionInfo.buildNumber)} 
    else {$c | Add-Member -Type NoteProperty -Name Version -Value $null}
	$creport += $c
    }
    $creport | % { $_.PSObject.TypeNames.Insert(0,"NSX.ManagerComponents") }
	return $creport

	} # End of process
} # End of function

function Set-NSXManagerSSH {
<#  

.SYNOPSIS  
    Configures NSX Manager SSH component

.DESCRIPTION 
    Will set SSH component information from NSX Manager

.NOTES  
    Author:  Kyle Ruddy, @kmruddy, thatcouldbeaproblem.com
	Binding, SSL and Authentication sections sourced from Chris Wahl's github repo: https://github.com/WahlNetwork/powershell-scripts/blob/master/VMware%20NSX/Get-NSXController.ps1

.PARAMETER NSXManager
	The FQDN or IP of your NSX Manager

.PARAMETER Username
	The username to connect with. Defaults to admin if nothing is provided.

.PARAMETER Password
	The password to connect with

.PARAMETER Enabled
    The desired state of SSH

.EXAMPLE
	PS> Set-NSXManagerSSH -NSXManager nsxmgr.fqdn -Username admin -Password password -Enabled $true
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
		[Boolean]$Enabled = $false
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

    if ($Enabled -eq $true) {$command = "Start"}
    else {$command = "Stop"}

	### Create authorization string and store in $head
	$auth = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Username + ":" + $Password))
	$head = @{"Authorization"="Basic $auth"}

	### Connect to NSX Manager via API
	$Request = "https://$NSXManager/api/1.0/appliance-management/components/component/SSH/toggleStatus/$command"
	$r = Invoke-RestMethod -Uri $Request -Headers $head -contenttype "application/xml" -ErrorAction:Stop -Method Post

	### Connect to NSX Manager via API
	$Request = "https://$NSXManager/api/1.0/appliance-management/components/component/SSH"
	$r = Invoke-RestMethod -Uri $Request -Headers $head -contenttype "application/xml" -ErrorAction:Stop -Method Get

	### Return the NSX Manager Info
    $creport = @()
    foreach ($comp in $r) {
    $c = New-Object System.Object
    $c | Add-Member -Type NoteProperty -Name ID -Value $comp.componentId
	$c | Add-Member -Type NoteProperty -Name Name -Value $comp.Name
	$c | Add-Member -Type NoteProperty -Name Description -Value $comp.Description
    $c | Add-Member -Type NoteProperty -Name Status -Value $comp.status
    $c | Add-Member -Type NoteProperty -Name Enabled -Value $comp.enabled
    $c | Add-Member -Type NoteProperty -Name ShowLogs -Value $comp.showTechSupportLogs
    if ($comp.uses) {$c | Add-Member -Type NoteProperty -Name Uses -Value ($comp.uses -join ", ")} 
    else {$c | Add-Member -Type NoteProperty -Name Uses -Value $null}
    if ($comp.usedBy) {$c | Add-Member -Type NoteProperty -Name UsedBy -Value ($comp.usedBy -join ", ")} 
    else {$c | Add-Member -Type NoteProperty -Name UsedBy -Value $null}
    $c | Add-Member -Type NoteProperty -Name ComponentGroup -Value $comp.componentGroup
    if ($comp.versionInfo) {$c | Add-Member -Type NoteProperty -Name Version -Value ($comp.versionInfo.majorVersion + "." + $comp.versionInfo.minorVersion + "." + $comp.versionInfo.patchVersion + " Build " + $comp.versionInfo.buildNumber)} 
    else {$c | Add-Member -Type NoteProperty -Name Version -Value $null}
	$creport += $c
    }
    $creport | % { $_.PSObject.TypeNames.Insert(0,"NSX.ManagerComponents") }
	return $creport

	} # End of process
} # End of function

function Update-NSXEdge {
<#  
.SYNOPSIS  
    Updates the NSX Edge via Update parameter

.DESCRIPTION 
    Applies update to indicated NSX Edge

.NOTES  
    Author:  Kyle Ruddy, @kmruddy, thatcouldbeaproblem.com
	Binding, SSL and Authentication sections sourced from Chris Wahl's github repo: https://github.com/WahlNetwork/powershell-scripts/blob/master/VMware%20NSX/Get-NSXController.ps1

.PARAMETER NSXManager
	The FQDN or IP of your NSX Manager

.PARAMETER Username
	The username to connect with. Defaults to admin if nothing is provided.

.PARAMETER Password
	The password to connect with

.PARAMETER EdgeID
	The Edge Node ID to pull information from

.Parameter Update
    A true/false parameter used to engage an already updated update

.EXAMPLE
	PS> Update-NSXEdge -NSXManager nsxmgr.fqdn -Username admin -Password password -EdgeID edge-1 -Update $true
#>
[CmdletBinding()] 
	param(
		[Parameter(Mandatory=$true,Position=0)]
		[String]$NSXManager,
		[Parameter(Mandatory=$false,Position=1)]
		[String]$Username = "admin",
		[Parameter(Mandatory=$true,Position=2)]
		[String]$Password,
		[Parameter(Mandatory=$true,Position=3)]
		[String]$Edgeid,
        [Parameter(Mandatory=$false)]
		[Boolean]$Update = $false
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

    if ($Upgrade -eq $true) {

	### Connect to NSX Manager via API
	$Request = "https://$NSXManager/api/4.0/edges/$Edgeid"
	$r = Invoke-WebRequest -Uri $Request -Headers $head -ContentType "application/xml" -ErrorAction:Stop
	if ($r.StatusCode -eq "200") {
	### Connect to NSX Manager via API
	$erequest = ("https://" + $NSXManager + "/api/3.0/edges/" + $Edgeid + "?action=upgrade")
	$e = Invoke-RestMethod -Uri $erequest -Headers $head -contenttype "application/xml" -ErrorAction:SilentlyContinue -Method POST
    
    Start-Sleep -Seconds 5
    	
	$Request = "https://$NSXManager/api/4.0/edges/"
	$c = Invoke-WebRequest -Uri $Request -Headers $head -ContentType "application/xml" -ErrorAction:Stop
		
	### Return the NSX Edge Nodes
	$ereport = @()
	foreach ($edge in $c.pagedEdgeList.edgePage.edgeSummary)
		{
        if ($edge.id -eq $Edgeid) {
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
	return $ereport}

    }
    else {Write-Error "Edge-ID not found."}

    }

	} # End of process
} # End of function

function Remove-NSXEdge {
<#  
.SYNOPSIS  
    Deletes an NSX Edge Node from NSX Manager

.DESCRIPTION 
    Will delete the selected Edge Node from NSX Manager

.NOTES  
    Author:  Kyle Ruddy, @kmruddy, thatcouldbeaproblem.com
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
	PS> Remove-NSXEdgeInterfaces -NSXManager nsxmgr.fqdn -Username admin -Password password -EdgeID edge-1
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
	$r = Invoke-WebRequest  -Uri $Request -Headers $head -Method Delete -ErrorAction:Stop
	
	} # End of process
} # End of function

function Get-NSXEdge {
<#  
.SYNOPSIS  
    Gathers NSX Edge Node details from NSX Manager

.DESCRIPTION 
    Will inventory a single Edge Node from NSX Manager

.NOTES  
    Author:  Kyle Ruddy, @kmruddy, thatcouldbeaproblem.com
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
	PS> Get-NSXEdge -NSXManager nsxmgr.fqdn -Username admin -Password password -EdgeID edge-1
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
	$Request = "https://$NSXManager/api/4.0/edges/$edgeid"
	$r = Invoke-RestMethod -Uri $Request -Headers $head -ContentType "application/xml" -ErrorAction:Stop
		
	### Return the NSX Edge Nodes
	$ereport = @()
	foreach ($edge in $r.edge)
		{
		$e = New-Object System.Object
		$e | Add-Member -Type NoteProperty -Name ID -Value $edge.id
		$e | Add-Member -Type NoteProperty -Name Name -Value $edge.name
		$e | Add-Member -Type NoteProperty -Name Status -Value $edge.status
		$e | Add-Member -Type NoteProperty -Name Version -Value $edge.version
        $e | Add-Member -Type NoteProperty -Name Type -Value $edge.type
        $e | Add-Member -Type NoteProperty -Name Size -Value $edge.appliances.applianceSize
		$e | Add-Member -Type NoteProperty -Name SSHEnabled -Value $edge.cliSettings.remoteAccess
		$ereport += $e
		}
	$ereport | % { $_.PSObject.TypeNames.Insert(0,"NSX.Edge") }
	return $ereport

	} # End of process
} # End of function

function Get-NSXScopes {
<#  
.SYNOPSIS  
    Gathers NSX Scopes and their details from NSX Manager

.DESCRIPTION 
    Will inventory the NSX scopes from NSX Manager

.NOTES  
    Author:  Kyle Ruddy, @kmruddy, thatcouldbeaproblem.com
	Binding, SSL and Authentication sections sourced from Chris Wahl's github repo: https://github.com/WahlNetwork/powershell-scripts/blob/master/VMware%20NSX/Get-NSXController.ps1

.PARAMETER NSXManager
	The FQDN or IP of your NSX Manager

.PARAMETER Username
	The username to connect with. Defaults to admin if nothing is provided.

.PARAMETER Password
	The password to connect with

.EXAMPLE
	PS> Get-NSXScopes -NSXManager nsxmgr.fqdn -Username admin -Password password
#>
[CmdletBinding()] 
	param(
		[Parameter(Mandatory=$true,Position=0)]
		[String]$NSXManager,
		[Parameter(Mandatory=$false,Position=1)]
		[String]$Username = "admin",
		[Parameter(Mandatory=$true,Position=2)]
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
	$Request = "https://$NSXManager/api/2.0/vdn/scopes"
	$r = Invoke-RestMethod -Uri $Request -Headers $head -ContentType "application/xml" -ErrorAction:Stop
		
	### Return the NSX Scopes
	$sreport = @()
	foreach ($scope in $r.vdnScopes.vdnScope)
		{
		$s = New-Object System.Object
		$s | Add-Member -Type NoteProperty -Name ID -Value $scope.id
		$s | Add-Member -Type NoteProperty -Name Name -Value $scope.name
		$s | Add-Member -Type NoteProperty -Name Mode -Value $scope.controlPlaneMode
		$s | Add-Member -Type NoteProperty -Name LogicalSwitchCount -Value $scope.virtualWireCount
        $sreport += $s
		}
	return $sreport

	} # End of process
} # End of function

function Get-NSXLogicalSwitches {
<#  
.SYNOPSIS  
    Gathers NSX Logical Switches and their details from NSX Manager

.DESCRIPTION 
    Will inventory the NSX Logical Switches from NSX Manager

.NOTES  
    Author:  Kyle Ruddy, @kmruddy, thatcouldbeaproblem.com
	Binding, SSL and Authentication sections sourced from Chris Wahl's github repo: https://github.com/WahlNetwork/powershell-scripts/blob/master/VMware%20NSX/Get-NSXController.ps1

.PARAMETER NSXManager
	The FQDN or IP of your NSX Manager

.PARAMETER Username
	The username to connect with. Defaults to admin if nothing is provided.

.PARAMETER Password
	The password to connect with

.EXAMPLE
	PS> Get-NSXLogicalSwitches -NSXManager nsxmgr.fqdn -Username admin -Password password
#>
[CmdletBinding()] 
	param(
		[Parameter(Mandatory=$true,Position=0)]
		[String]$NSXManager,
		[Parameter(Mandatory=$false,Position=1)]
		[String]$Username = "admin",
		[Parameter(Mandatory=$true,Position=2)]
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
	$Request = "https://$NSXManager/api/2.0/vdn/virtualwires?pagesize=300&startindex=00"
	$r = Invoke-RestMethod -Uri $Request -Headers $head -ContentType "application/xml" -ErrorAction:Stop -Method Get
		
	### Return the NSX Logical Switches
	$sreport = @()
	foreach ($scope in $r.virtualWires.dataPage.virtualWire)
		{
		$s = New-Object System.Object
		$s | Add-Member -Type NoteProperty -Name ID -Value $scope.objectId
		$s | Add-Member -Type NoteProperty -Name Name -Value $scope.name
        $s | Add-Member -Type NoteProperty -Name Mode -Value $scope.controlPlaneMode		
        $s | Add-Member -Type NoteProperty -Name MulticastAddress -Value $scope.multicastAddr
        $s | Add-Member -Type NoteProperty -Name VDSwitch -Value $scope.vdsContextWithBacking.switch.name
        if ($scope.description) {$s | Add-Member -Type NoteProperty -Name Description -Value $scope.description}
		else {$s | Add-Member -Type NoteProperty -Name Description -Value $null}
        
        $sreport += $s
		}
	$sreport | % { $_.PSObject.TypeNames.Insert(0,"NSX.LogicalSwitch") }
	return $sreport

	} # End of process
} # End of function

function New-NSXLogicalSwitch {
<#  
.SYNOPSIS  
    Gathers NSX Logical Switches and their details from NSX Manager

.DESCRIPTION 
    Will inventory the NSX Logical Switches from NSX Manager

.NOTES  
    Author:  Kyle Ruddy, @kmruddy, thatcouldbeaproblem.com
	Binding, SSL and Authentication sections sourced from Chris Wahl's github repo: https://github.com/WahlNetwork/powershell-scripts/blob/master/VMware%20NSX/Get-NSXController.ps1

.PARAMETER NSXManager
	The FQDN or IP of your NSX Manager

.PARAMETER Username
	The username to connect with. Defaults to admin if nothing is provided.

.PARAMETER Password
	The password to connect with

.PARAMETER Name
	The desired name of a new Logical Switch

.EXAMPLE
	PS> New-NSXLogicalSwitch -NSXManager nsxmgr.fqdn -Username admin -Password password -Name newlogicalswitch
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
		[String]$Name
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
	$vwrequest = "https://$NSXManager/api/2.0/vdn/virtualwires?pagesize=300&startindex=00"
	$vws = (Invoke-RestMethod -Uri $vwrequest -Headers $head -ContentType "application/xml" -ErrorAction:Stop -Method Get).virtualWires.dataPage.virtualWire

    if ($vws | ?{$_.Name -like $Name}) {Write-Warning "$name - Logical Switch already exists.";exit}
    [xml]$body = "<virtualWireCreateSpec><name>$Name</name><tenantId></tenantId></virtualWireCreateSpec>"


	$srequest = "https://$NSXManager/api/2.0/vdn/scopes"
	$scope = (Invoke-RestMethod -Uri $srequest -Headers $head -ContentType "application/xml" -ErrorAction:Stop).vdnScopes.vdnScope

    if ($scope -is [system.array]) {

    Write-Host "`nMultiple NSX Scopes found, please select one."
    $swmenu = @{}
    for ($i=1;$i -le $scope.count; $i++) {
        Write-Host "$i. $($scope[$i-1].Name)"
        $swmenu.Add($i,($scope[$i-1].Name))
        }
    [int]$sans = Read-Host 'Enter desired scope'
    if ($sans -eq '0' -or $sans -gt $i) {Write-Host -ForegroundColor Red  -Object "Invalid selection.`n";Exit}
    $scopeid = ($scope | ?{$_.Name -eq ($swmenu.Item($sans))}).objectId

    }
    else {$scopeid = $scope.objectId}

	### Connect to NSX Manager via API
	$Uri = "https://$NSXManager/api/2.0/vdn/scopes/$scopeid/virtualwires"
	$r = Invoke-RestMethod -Uri $Uri -Headers $head -ContentType "application/xml" -ErrorAction:Stop -Method Post -Body $body
	
    $Request = "https://$NSXManager/api/2.0/vdn/virtualwires/$r"
    $l = Invoke-RestMethod -Uri $Request -Headers $head -ContentType "application/xml" -ErrorAction:Stop -Method Get

	### Return the NSX Logical Switches
	$lsreport = @()
	foreach ($lswitch in $l.virtualWire)
		{
		$s = New-Object System.Object
		$s | Add-Member -Type NoteProperty -Name ID -Value $lswitch.objectId
		$s | Add-Member -Type NoteProperty -Name Name -Value $lswitch.name
        $s | Add-Member -Type NoteProperty -Name Mode -Value $lswitch.controlPlaneMode		
        $s | Add-Member -Type NoteProperty -Name MulticastAddress -Value $lswitch.multicastAddr
        $s | Add-Member -Type NoteProperty -Name VDSwitch -Value $lswitch.vdsContextWithBacking.switch.name
        if ($lswitch.description) {$s | Add-Member -Type NoteProperty -Name Description -Value $lswitch.description}
		else {$s | Add-Member -Type NoteProperty -Name Description -Value $null}
        
        $lsreport += $s
		}
	$lsreport | % { $_.PSObject.TypeNames.Insert(0,"NSX.LogicalSwitch") }
	return $lsreport

	} # End of process
} # End of function

function Remove-NSXLogicalSwitch {
<#  
.SYNOPSIS  
    Gathers NSX Logical Switches and their details from NSX Manager

.DESCRIPTION 
    Will inventory the NSX Logical Switches from NSX Manager

.NOTES  
    Author:  Kyle Ruddy, @kmruddy, thatcouldbeaproblem.com
	Binding, SSL and Authentication sections sourced from Chris Wahl's github repo: https://github.com/WahlNetwork/powershell-scripts/blob/master/VMware%20NSX/Get-NSXController.ps1

.PARAMETER NSXManager
	The FQDN or IP of your NSX Manager

.PARAMETER Username
	The username to connect with. Defaults to admin if nothing is provided.

.PARAMETER Password
	The password to connect with

.PARAMETER ID
	The Logical Switch ID to remove

.PARAMETER Name
	The Logical Switch name to remove

.EXAMPLE
	PS> Get-NSXLogicalSwitches -NSXManager nsxmgr.fqdn -Username admin -Password password -ID virtualwire-11

.EXAMPLE
    PS> Get-NSXLogicalSwitches -NSXManager nsxmgr.fqdn -Username admin -Password password -Name logicalswitchname
#>
[CmdletBinding()] 
	param(
		[Parameter(Mandatory=$true,Position=0)]
		[String]$NSXManager,
		[Parameter(Mandatory=$false,Position=1)]
		[String]$Username = "admin",
		[Parameter(Mandatory=$true,Position=2)]
		[String]$Password,
		[Parameter(Mandatory=$false,Position=3)]
		[String]$ID,
		[Parameter(Mandatory=$false)]
		[String]$Name
  	)

	Process {
    
    if (!$ID -and !$Name) {Write-Warning "Please enter either an ID or a Name.";exit}

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

    if ($name -and !$ID) {
	### Connect to NSX Manager via API
	$Request = "https://$NSXManager/api/2.0/vdn/virtualwires?pagesize=300&startindex=00"
	$r = (Invoke-RestMethod -Uri $Request -Headers $head -ContentType "application/xml" -ErrorAction:Stop -Method Get).virtualWires.dataPage.virtualWire
    $ID = ($r | ?{$_.Name -like $Name}).objectId
    if (!$ID) {Write-Warning "No Logical Switch found.";exit}
    }
    
    $Delete = "https://$NSXManager/api/2.0/vdn/virtualwires/$ID"
    $r = Invoke-WebRequest -Uri $Delete -Headers $head -ErrorAction:Stop -Method Delete

	} # End of process
} # End of function

function Get-NSXEdgeDefaultRoute {
<#  
.SYNOPSIS  
    Gathers NSX Edge Node default route details from NSX Manager

.DESCRIPTION 
    Will inventory a single Edge Node's default route from NSX Manager

.NOTES  
    Author:  Kyle Ruddy, @kmruddy, thatcouldbeaproblem.com
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
	PS> Get-NSXEdgeDefaultRoute -NSXManager nsxmgr.fqdn -Username admin -Password password -EdgeID edge-1
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
	$Info = "https://$NSXManager/api/4.0/edges/$edgeid"
    $Route = "https://$NSXManager/api/4.0/edges/$edgeid/routing/config/static"
    $i = Invoke-RestMethod -Uri $Info -Headers $head -ContentType "application/xml" -ErrorAction:Stop
	$r = Invoke-RestMethod -Uri $Route -Headers $head -ContentType "application/xml" -ErrorAction:Stop
		
	### Return the NSX Edge Node and Info
	$ereport = @()
	$e = New-Object System.Object
	$e | Add-Member -Type NoteProperty -Name ID -Value $i.edge.id
	$e | Add-Member -Type NoteProperty -Name Name -Value $i.edge.name
	$e | Add-Member -Type NoteProperty -Name VNIC -Value $r.staticRouting.defaultRoute.vnic
	$e | Add-Member -Type NoteProperty -Name MTU -Value $r.staticRouting.defaultRoute.mtu
    $e | Add-Member -Type NoteProperty -Name Gateway -Value $r.staticRouting.defaultRoute.gatewayAddress
    $ereport += $e
	$ereport | % { $_.PSObject.TypeNames.Insert(0,"NSX.DefaultRoute") }
	return $ereport

	} # End of process
} # End of function

function Get-NSXEdgeStaticRoute {
<#  
.SYNOPSIS  
    Gathers NSX Edge Node static route details from NSX Manager

.DESCRIPTION 
    Will inventory a single Edge Node's static route from NSX Manager

.NOTES  
    Author:  Kyle Ruddy, @kmruddy, thatcouldbeaproblem.com
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
	PS> Get-NSXEdgeStaticRoute -NSXManager nsxmgr.fqdn -Username admin -Password password -EdgeID edge-1
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
	$Info = "https://$NSXManager/api/4.0/edges/$edgeid"
    $Route = "https://$NSXManager/api/4.0/edges/$edgeid/routing/config/static"
    $i = Invoke-RestMethod -Uri $Info -Headers $head -ContentType "application/xml" -ErrorAction:Stop
	$r = Invoke-RestMethod -Uri $Route -Headers $head -ContentType "application/xml" -ErrorAction:Stop
		
	### Return the NSX Edge Node and Info
	$ereport = @()
    foreach ($sroute in $r.staticRouting.staticRoutes.route) {
	$e = New-Object System.Object
	$e | Add-Member -Type NoteProperty -Name ID -Value $i.edge.id
	$e | Add-Member -Type NoteProperty -Name Name -Value $i.edge.name
	$e | Add-Member -Type NoteProperty -Name VNIC -Value $sroute.vnic
    $e | Add-Member -Type NoteProperty -Name MTU -Value $sroute.mtu	
    $e | Add-Member -Type NoteProperty -Name Network -Value $sroute.network
    $e | Add-Member -Type NoteProperty -Name NextHop -Value $sroute.nextHop
    if ($sroute.description) {$e | Add-Member -Type NoteProperty -Name Description -Value $sroute.description}
    else {$e | Add-Member -Type NoteProperty -Name Description -Value $null}
    $ereport += $e
    }
	$ereport | % { $_.PSObject.TypeNames.Insert(0,"NSX.StaticRoute") }
	return $ereport

	} # End of process
} # End of function

function Get-NSXEdgeFirewall {
<#  
.SYNOPSIS  
    Gathers NSX Edge Node firewall details from NSX Manager

.DESCRIPTION 
    Will inventory a single Edge Node's firewall from NSX Manager

.NOTES  
    Author:  Kyle Ruddy, @kmruddy, thatcouldbeaproblem.com
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
	PS> Get-NSXEdgeFirewall -NSXManager nsxmgr.fqdn -Username admin -Password password -EdgeID edge-1
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
	$Info = "https://$NSXManager/api/4.0/edges/$edgeid"
    $Firewall = "https://$NSXManager/api/4.0/edges/$edgeid/firewall/config"
    $i = Invoke-RestMethod -Uri $Info -Headers $head -ContentType "application/xml" -ErrorAction:Stop
	$f = Invoke-RestMethod -Uri $Firewall -Headers $head -ContentType "application/xml" -ErrorAction:Stop
		
	### Return the NSX Edge Node and Info
	$ereport = @()
    foreach ($fw in $f.firewall) {
	$e = New-Object System.Object
	$e | Add-Member -Type NoteProperty -Name ID -Value $i.edge.id
	$e | Add-Member -Type NoteProperty -Name Name -Value $i.edge.name
	$e | Add-Member -Type NoteProperty -Name Version -Value $fw.version
    $e | Add-Member -Type NoteProperty -Name Enabled -Value $fw.enabled	
    $e | Add-Member -Type NoteProperty -Name DefaultAction -Value $fw.defaultPolicy.action
    if ($fw.defaultPolicy.loggingEnabled -eq $true) {$e | Add-Member -Type NoteProperty -Name Logging -Value "Enabled"}
    else {$e | Add-Member -Type NoteProperty -Name Logging -Value "Disabled"}
    $ereport += $e
    }
	$ereport | % { $_.PSObject.TypeNames.Insert(0,"NSX.Firewall") }
	return $ereport

	} # End of process
} # End of function

function Get-NSXSSOConfig {
<#  
.SYNOPSIS  
    Gathers NSX SSO details from NSX Manager

.DESCRIPTION 
    Will inventory the SSO config details from NSX Manager

.NOTES  
    Author:  Kyle Ruddy, @kmruddy, thatcouldbeaproblem.com
	Binding, SSL and Authentication sections sourced from Chris Wahl's github repo: https://github.com/WahlNetwork/powershell-scripts/blob/master/VMware%20NSX/Get-NSXController.ps1

.PARAMETER NSXManager
	The FQDN or IP of your NSX Manager

.PARAMETER Username
	The username to connect with. Defaults to admin if nothing is provided.

.PARAMETER Password
	The password to connect with

.EXAMPLE
	PS> Get-NSXSSOConfig -NSXManager nsxmgr.fqdn -Username admin -Password password
#>
[CmdletBinding()] 
	param(
		[Parameter(Mandatory=$true,Position=0)]
		[String]$NSXManager,
		[Parameter(Mandatory=$false,Position=1)]
		[String]$Username = "admin",
		[Parameter(Mandatory=$true,Position=2)]
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
	$Info = "https://$NSXManager/api/2.0/services/ssoconfig"
    $i = Invoke-RestMethod -Uri $Info -Headers $head -ContentType "application/xml" -ErrorAction:Stop
		
	### Return the NSX Edge Node and Info
	$ereport = @()
	$e = New-Object System.Object
	$e | Add-Member -Type NoteProperty -Name Solution -Value $i.ssoconfig.vsmSolutionName
	$e | Add-Member -Type NoteProperty -Name LookupURL -Value $i.ssoconfig.ssolookupserviceurl
	$e | Add-Member -Type NoteProperty -Name Username -Value $i.ssoconfig.ssoadminusername
	$ereport += $e
	return $ereport

	} # End of process
} # End of function

function Remove-NSXSSOConfig {
<#  
.SYNOPSIS  
    Removes NSX SSO config from NSX Manager

.DESCRIPTION 
    Will remove the SSO config details from NSX Manager

.NOTES  
    Author:  Kyle Ruddy, @kmruddy, thatcouldbeaproblem.com
	Binding, SSL and Authentication sections sourced from Chris Wahl's github repo: https://github.com/WahlNetwork/powershell-scripts/blob/master/VMware%20NSX/Get-NSXController.ps1

.PARAMETER NSXManager
	The FQDN or IP of your NSX Manager

.PARAMETER Username
	The username to connect with. Defaults to admin if nothing is provided.

.PARAMETER Password
	The password to connect with

.EXAMPLE
	PS> Remove-NSXSSOConfig -NSXManager nsxmgr.fqdn -Username admin -Password password
#>
[CmdletBinding()] 
	param(
		[Parameter(Mandatory=$true,Position=0)]
		[String]$NSXManager,
		[Parameter(Mandatory=$false,Position=1)]
		[String]$Username = "admin",
		[Parameter(Mandatory=$true,Position=2)]
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
	$Info = "https://$NSXManager/api/2.0/services/ssoconfig"
    $i = Invoke-RestMethod -Uri $Info -Headers $head -ContentType "application/xml" -ErrorAction:Stop -Method Delete

	} # End of process
} # End of function	

function Get-NSXIPSets {
<#  
.SYNOPSIS  
    Gathers NSX IP Set details from NSX Manager

.DESCRIPTION 
    Will inventory the IP Set details from NSX Manager

.NOTES  
    Author:  Kyle Ruddy, @kmruddy, thatcouldbeaproblem.com
	Binding, SSL and Authentication sections sourced from Chris Wahl's github repo: https://github.com/WahlNetwork/powershell-scripts/blob/master/VMware%20NSX/Get-NSXController.ps1

.PARAMETER NSXManager
	The FQDN or IP of your NSX Manager

.PARAMETER Username
	The username to connect with. Defaults to admin if nothing is provided.

.PARAMETER Password
	The password to connect with

.EXAMPLE
	PS> Get-NSXIPSets -NSXManager nsxmgr.fqdn -Username admin -Password password
#>
[CmdletBinding()] 
	param(
		[Parameter(Mandatory=$true,Position=0)]
		[String]$NSXManager,
		[Parameter(Mandatory=$false,Position=1)]
		[String]$Username = "admin",
		[Parameter(Mandatory=$true,Position=2)]
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
	$Info = "https://$NSXManager/api/2.0/services/ipset/scope/globalroot-0"
    $i = Invoke-RestMethod -Uri $Info -Headers $head -ContentType "application/xml" -ErrorAction:Stop
		
	### Return the NSX Edge Node and Info
	$ireport = @()
    foreach ($ips in $i.list.ipset) {
    if ($ips.value) {
	$e = New-Object System.Object
	$e | Add-Member -Type NoteProperty -Name ID -Value $ips.objectId
	$e | Add-Member -Type NoteProperty -Name Name -Value $ips.name
    if ($ips.description) {$e | Add-Member -Type NoteProperty -Name Description -Value ($ips.description).TrimStart("`n").TrimEnd("`n")}
    else {$e | Add-Member -Type NoteProperty -Name Description -Value ""}
    $e | Add-Member -Type NoteProperty -Name Details -Value $ips.value
    $e | Add-Member -Type NoteProperty -Name Scope -Value $ips.scope.name
    $e | Add-Member -Type NoteProperty -Name Inheritance -Value $ips.inheritanceAllowed
    $ireport += $e
    }
    }
    $ireport | % { $_.PSObject.TypeNames.Insert(0,"NSX.IPSet") }
	return $ireport

	} # End of process
} # End of function

function New-NSXIPSet {
<#  
.SYNOPSIS  
    Creates a new NSX IP Set within NSX Manager

.DESCRIPTION 
    Will create a new IP Set inside the NSX Manager

.NOTES  
    Author:  Kyle Ruddy, @kmruddy, thatcouldbeaproblem.com
	Binding, SSL and Authentication sections sourced from Chris Wahl's github repo: https://github.com/WahlNetwork/powershell-scripts/blob/master/VMware%20NSX/Get-NSXController.ps1

.PARAMETER NSXManager
	The FQDN or IP of your NSX Manager

.PARAMETER Username
	The username to connect with. Defaults to admin if nothing is provided.

.PARAMETER Password
	The password to connect with

.PARAMETER Name
	The desired name for a new IP Set

.PARAMETER Description
	The desired description for a new IP Set

.PARAMETER IPAddresses
	The desired IP Address, IP Addresses, and/or IP Address range for a new IP Set

.EXAMPLE
	PS> New-NSXIPSet -NSXManager nsxmgr.fqdn -Username admin -Password password -Name ipsetname -Description "IP Set Description" -IPAddresses "192.168.200.1,192.168.200.1/24, 192.168.200.1-192.168.200.24"
#>
[CmdletBinding()] 
	param(
		[Parameter(Mandatory=$true,Position=0)]
		[String]$NSXManager,
		[Parameter(Mandatory=$false,Position=1)]
		[String]$Username = "admin",
		[Parameter(Mandatory=$true,Position=2)]
		[String]$Password,
		[Parameter(Mandatory=$true,Position=3)]
		[String]$Name,
		[Parameter(Mandatory=$false,Position=4)]
		[String]$Description,
		[Parameter(Mandatory=$true)]
		[String]$IPAddresses
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

    if ($description) {[xml]$body = "<ipset><description>$Description</description><name>$Name</name><value>$IPAddresses</value></ipset>"}
    else {[xml]$body = "<ipset><name>$Name</name><value>$IPAddresses</value></ipset>"}

	### Connect to NSX Manager via API
	$New = "https://$NSXManager/api/2.0/services/ipset/globalroot-0"
    $n = Invoke-RestMethod -Uri $New -Headers $head -ContentType "application/xml" -ErrorAction:Stop -Method Post -Body $body
		
    $Info = "https://$NSXManager/api/2.0/services/ipset/$n"
    $i = Invoke-RestMethod -Uri $Info -Headers $head -ContentType "application/xml" -ErrorAction:Stop

	### Return the NSX Edge Node and Info
	$ireport = @()
    foreach ($ips in $i.ipset) {
    if ($ips.value) {
	$e = New-Object System.Object
	$e | Add-Member -Type NoteProperty -Name ID -Value $ips.objectId
	$e | Add-Member -Type NoteProperty -Name Name -Value $ips.name
    if ($ips.description) {$e | Add-Member -Type NoteProperty -Name Description -Value ($ips.description).TrimStart("`n").TrimEnd("`n")}
    else {$e | Add-Member -Type NoteProperty -Name Description -Value ""}
    $e | Add-Member -Type NoteProperty -Name Details -Value $ips.value
    $e | Add-Member -Type NoteProperty -Name Scope -Value $ips.scope.name
    $e | Add-Member -Type NoteProperty -Name Inheritance -Value $ips.inheritanceAllowed
    $ireport += $e
    }
    }
    $ireport | % { $_.PSObject.TypeNames.Insert(0,"NSX.IPSet") }
	return $ireport

	} # End of process
} # End of function

function Remove-NSXIPSet {
<#  
.SYNOPSIS  
    Removes an NSX IP Set within NSX Manager

.DESCRIPTION 
    Will delete a new IP Set inside the NSX Manager

.NOTES  
    Author:  Kyle Ruddy, @kmruddy, thatcouldbeaproblem.com
	Binding, SSL and Authentication sections sourced from Chris Wahl's github repo: https://github.com/WahlNetwork/powershell-scripts/blob/master/VMware%20NSX/Get-NSXController.ps1

.PARAMETER NSXManager
	The FQDN or IP of your NSX Manager

.PARAMETER Username
	The username to connect with. Defaults to admin if nothing is provided.

.PARAMETER Password
	The password to connect with

.PARAMETER IPSetID
	The IP Set ID to remove

.PARAMETER Force
	A true/false parameter to force the removal of an IP Set

.EXAMPLE
	PS> Remove-NSXIPSet -NSXManager nsxmgr.fqdn -Username admin -Password password -IPSetID ipset-2 -Force $true
#>
[CmdletBinding()] 
	param(
		[Parameter(Mandatory=$true,Position=0)]
		[String]$NSXManager,
		[Parameter(Mandatory=$false,Position=1)]
		[String]$Username = "admin",
		[Parameter(Mandatory=$true,Position=2)]
		[String]$Password,
		[Parameter(Mandatory=$true,Position=3)]
		[String]$IPSetID,
		[Parameter(Mandatory=$false)]
		[Boolean]$Force = $false
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
	if ($force -eq $true) {$Info = "https://$NSXManager/api/2.0/services/ipset/" + $ipsetid + "?force=true"}
    else {$Info = "https://$NSXManager/api/2.0/services/ipset/$ipsetid"}
    $n = Invoke-RestMethod -Uri $Info -Headers $head -ContentType "application/xml" -ErrorAction:Stop -Method Delete

	} # End of process
} # End of function

function Get-NSXIPPools {
<#  
.SYNOPSIS  
    Gathers NSX IP Pool details from NSX Manager

.DESCRIPTION 
    Will inventory the IP Pool details from NSX Manager

.NOTES  
    Author:  Kyle Ruddy, @kmruddy, thatcouldbeaproblem.com
	Binding, SSL and Authentication sections sourced from Chris Wahl's github repo: https://github.com/WahlNetwork/powershell-scripts/blob/master/VMware%20NSX/Get-NSXController.ps1

.PARAMETER NSXManager
	The FQDN or IP of your NSX Manager

.PARAMETER Username
	The username to connect with. Defaults to admin if nothing is provided.

.PARAMETER Password
	The password to connect with

.EXAMPLE
	PS> Get-NSXIPPools -NSXManager nsxmgr.fqdn -Username admin -Password password
#>
[CmdletBinding()] 
	param(
		[Parameter(Mandatory=$true,Position=0)]
		[String]$NSXManager,
		[Parameter(Mandatory=$false,Position=1)]
		[String]$Username = "admin",
		[Parameter(Mandatory=$true,Position=2)]
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
	$Info = "https://$NSXManager/api/2.0/services/ipam/pools/scope/globalroot-0"
    $i = Invoke-RestMethod -Uri $Info -Headers $head -ContentType "application/xml" -ErrorAction:Stop
		
	### Return the NSX Edge Node and Info
	$ireport = @()
    foreach ($ipp in $i.ipamaddresspools.ipamaddresspool) {
	$e = New-Object System.Object
	$e | Add-Member -Type NoteProperty -Name ID -Value $ipp.objectId
	$e | Add-Member -Type NoteProperty -Name Name -Value $ipp.name
    $e | Add-Member -Type NoteProperty -Name Range -Value ($ipp.ipranges.iprangedto.startaddress + "-" + $ipp.ipranges.iprangedto.endaddress)
    $e | Add-Member -Type NoteProperty -Name Prefix -Value $ipp.prefixlength
    $e | Add-Member -Type NoteProperty -Name Gateway -Value $ipp.gateway
    $e | Add-Member -Type NoteProperty -Name UsedTotal -Value ($ipp.usedaddresscount + "/" + $ipp.totaladdresscount)
    $e | Add-Member -Type NoteProperty -Name DNSSuffix -Value $ipp.dnssuffix
    $e | Add-Member -Type NoteProperty -Name PrimaryDNS -Value $ipp.dnsserver1
    $e | Add-Member -Type NoteProperty -Name SecondaryDNS -Value $ipp.dnsserver2
    $ireport += $e
    }
    $ireport | % { $_.PSObject.TypeNames.Insert(0,"NSX.IPPool") }
	return $ireport

	} # End of process
} # End of function

function New-NSXIPPool {
<#  
.SYNOPSIS  
    Creates an NSX IP Pool within NSX Manager

.DESCRIPTION 
    Will create a new IP Pool within NSX Manager

.NOTES  
    Author:  Kyle Ruddy, @kmruddy, thatcouldbeaproblem.com
	Binding, SSL and Authentication sections sourced from Chris Wahl's github repo: https://github.com/WahlNetwork/powershell-scripts/blob/master/VMware%20NSX/Get-NSXController.ps1

.PARAMETER NSXManager
	The FQDN or IP of your NSX Manager

.PARAMETER Username
	The username to connect with. Defaults to admin if nothing is provided.

.PARAMETER Password
	The password to connect with

.PARAMETER Name
	The desired name for a new IP Pool

.PARAMETER IPPoolStart
	The desired starting IP Address for a new IP Pool

.PARAMETER IPPoolEnd
	The desired ending IP Address for a new IP Pool

.PARAMETER Prefix
	The desired subnet prefix for a new IP Pool

.PARAMETER Gateway
	The desired gateway for a new IP Pool

.PARAMETER PrimaryDNS
	The desired Primary DNS server for a new IP Pool

.PARAMETER SecondaryDNS
	The desired Secondary DNS server for a new IP Pool

.PARAMETER DNSSuffix
	The desired DNS suffix name for a new IP Pool

.EXAMPLE
	PS> Get-NSXIPPool -NSXManager nsxmgr.fqdn -Username admin -Password password -Name IPPoolName -IPPoolStart "192.168.1.2" -IPPoolEnd "192.168.1.100" -Prefix 24 -Gateway "192.168.1.254"

.EXAMPLE
	PS> Get-NSXIPPool -NSXManager nsxmgr.fqdn -Username admin -Password password -Name IPPoolName -IPPoolStart "192.168.1.2" -IPPoolEnd "192.168.1.100" -Prefix 24 -Gateway "192.168.1.254" -PrimaryDNS "192.168.10.10" -SecondaryDNS "192.168.10.11" -DNSSuffix "nsx.lab"
#>
[CmdletBinding()] 
	param(
		[Parameter(Mandatory=$true,Position=0)]
		[String]$NSXManager,
		[Parameter(Mandatory=$false,Position=1)]
		[String]$Username = "admin",
		[Parameter(Mandatory=$true,Position=2)]
		[String]$Password,
		[Parameter(Mandatory=$true,Position=3)]
		[String]$Name,
		[Parameter(Mandatory=$true,Position=4)]
		[IPAddress]$IPPoolStart,
		[Parameter(Mandatory=$true,Position=5)]
		[IPAddress]$IPPoolEnd,
		[Parameter(Mandatory=$false,Position=6)]
		[String]$Prefix = "24",
		[Parameter(Mandatory=$true,Position=7)]
		[IPAddress]$Gateway,
		[Parameter(Mandatory=$false,Position=8)]
		[IPAddress]$PrimaryDNS,
		[Parameter(Mandatory=$false,Position=9)]
		[IPAddress]$SecondaryDNS,
		[Parameter(Mandatory=$false)]
		[String]$DNSSuffix
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

    $body = "<ipamAddressPool><name>$Name</name><prefixLength>$Prefix</prefixLength><gateway>$Gateway</gateway>"
    if ($DNSSuffix) {$body += "<dnsSuffix>$DNSSuffix</dnsSuffix>"}
    if ($PrimaryDNS) {$body += "<dnsServer1>$PrimaryDNS</dnsServer1>"}
    if ($SecondaryDNS) {$body += "<dnsServer2>$SecondaryDNS</dnsServer2>"}
    $body += "<ipRanges><ipRangeDto><startAddress>$IPPoolStart</startAddress><endAddress>$IPPoolEnd</endAddress></ipRangeDto></ipRanges></ipamAddressPool>"
    $body = [xml]$body

	### Connect to NSX Manager via API
	$Post = "https://$NSXManager/api/2.0/services/ipam/pools/scope/globalroot-0"
    $p = Invoke-RestMethod -Uri $Post -Headers $head -ContentType "application/xml" -ErrorAction:Stop -Method Post -Body $body

    $Info = "https://$NSXManager/api/2.0/services/ipam/pools/$p"
    $i = Invoke-RestMethod -Uri $Info -Headers $head -ContentType "application/xml" -ErrorAction:Stop	
	
	### Return the NSX Edge Node and Info
	$ireport = @()
    foreach ($ipp in $i.ipamaddresspool) {
	$e = New-Object System.Object
	$e | Add-Member -Type NoteProperty -Name ID -Value $ipp.objectId
	$e | Add-Member -Type NoteProperty -Name Name -Value $ipp.name
    $e | Add-Member -Type NoteProperty -Name Range -Value ($ipp.ipranges.iprangedto.startaddress + "-" + $ipp.ipranges.iprangedto.endaddress)
    $e | Add-Member -Type NoteProperty -Name Prefix -Value $ipp.prefixlength
    $e | Add-Member -Type NoteProperty -Name Gateway -Value $ipp.gateway
    $e | Add-Member -Type NoteProperty -Name UsedTotal -Value ($ipp.usedaddresscount + "/" + $ipp.totaladdresscount)
    $e | Add-Member -Type NoteProperty -Name DNSSuffix -Value $ipp.dnssuffix
    $e | Add-Member -Type NoteProperty -Name PrimaryDNS -Value $ipp.dnsserver1
    $e | Add-Member -Type NoteProperty -Name SecondaryDNS -Value $ipp.dnsserver2
    $ireport += $e
    }
    $ireport | % { $_.PSObject.TypeNames.Insert(0,"NSX.IPPool") }
	return $ireport

	} # End of process
} # End of function

function Remove-NSXIPPool {
<#  
.Synopsis  
    Removes an NSX IP Pool within NSX Manager

.Description 
    Will delete a new IP Pool inside the NSX Manager

.Notes  
    Author:  Kyle Ruddy, @kmruddy, thatcouldbeaproblem.com
	Binding, SSL and Authentication sections sourced from Chris Wahl's github repo: https://github.com/WahlNetwork/powershell-scripts/blob/master/VMware%20NSX/Get-NSXController.ps1

.PARAMETER NSXManager
	The FQDN or IP of your NSX Manager

.PARAMETER Username
	The username to connect with. Defaults to admin if nothing is provided.

.PARAMETER Password
	The password to connect with

.PARAMETER IPPoolID
	The IP Pool ID to remove

.Example
	PS> Remove-NSXIPPool -NSXManager nsxmgr.fqdn -Username admin -Password password -IPPoolID ipaddresspool-2
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
		[String]$IPPoolID
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
	$Info = "https://$NSXManager/api/2.0/services/ipam/pools/$IPPoolID"
    $i = Invoke-RestMethod -Uri $Info -Headers $head -ContentType "application/xml" -ErrorAction:Stop -Method Delete

	} # End of process
} # End of function
