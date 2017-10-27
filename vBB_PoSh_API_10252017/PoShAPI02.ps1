$vCenter = 'vcsa01.corp.local'

# Authentication Header
$creds = Get-Credential
$auth = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($creds.UserName + ':' + $creds.GetNetworkCredential().Password))
$head = @{
    'Authorization' = "Basic $auth"
}

# Authentication - Login 
$authReq = Invoke-WebRequest -Uri "https://$vCenter/rest/com/vmware/cis/session" -Method Post -Headers $head
$token = (ConvertFrom-Json $authReq.Content).value
$session = @{'vmware-api-session-id' = $token}

# Appliance - Access - SSH - Get
$sshGetReq = Invoke-WebRequest -Uri "https://$vCenter/rest/appliance/access/ssh" -Method Get -Headers $session
$sshGetReq
$sshGet = (ConvertFrom-Json $sshGetReq.Content).value
$sshGet

$sshGetReq2 = Invoke-RestMethod -Uri "https://$vCenter/rest/appliance/access/ssh" -Method Get -Headers $session
$sshGetReq2

Measure-Command {Invoke-WebRequest -Uri "https://$vCenter/rest/appliance/access/ssh" -Method Get -Headers $session}
Measure-Command {Invoke-RestMethod -Uri "https://$vCenter/rest/appliance/access/ssh" -Method Get -Headers $session}

# Appliance - Access - SSH - Set
$sshSetReqBody = @{
    enabled =  $true
} | ConvertTo-Json 
$sshSetReq = Invoke-WebRequest -Uri "https://$vCenter/rest/appliance/access/ssh" -Method Put -Headers $session -Body $sshSetReqBody -ContentType 'application/json'
$sshSetReq
$sshGetReq = Invoke-WebRequest -Uri "https://$vCenter/rest/appliance/access/ssh" -Method Get -Headers $session
$sshGet = (ConvertFrom-Json $sshGetReq.Content).value
$sshGet

# vCenter - Host - Get
$vmhostGetReq = Invoke-WebRequest -Uri "https://$vCenter/rest/vcenter/host" -Method Get -Headers $session
$vmhostGet = (ConvertFrom-Json $vmhostGetReq.Content).value
$vmhostGet

# vCenter - Host - Disconnect
$hostId = "host-167"
$vmhostDisReq = Invoke-WebRequest -Uri "https://$vCenter/rest/vcenter/host/$hostId/disconnect" -Method Post -Headers $session
$vmhostDis = (ConvertFrom-Json $vmhostDisReq.Content).value
$vmhostDis

# vCenter - Host - Delete
$vmhostDelReq = Invoke-WebRequest -Uri "https://$vCenter/rest/vcenter/host/$hostId" -Method Post -Headers $session
$vmhostDel = (ConvertFrom-Json $vmhostDelReq.Content).value
$vmhostDel

# vCenter - Host - Add
$vmhostAddReqBody = @{
    spec = @{
        force_add = $true
        folder = "group-h43"
        hostname = "esx04.corp.local"
        user_name = "root"
        password = "VMware1!"
        port = "443"
        thumbprint_verification = "NONE"
    }
} | ConvertTo-Json
$vmhostAddReq = Invoke-WebRequest -Uri "https://$vCenter/rest/vcenter/host" -Method Post -Headers $session -Body $vmhostAddReqBody
$vmhostAddReq
$vmhostGetReq = Invoke-WebRequest -Uri "https://$vCenter/rest/vcenter/host" -Method Get -Headers $session
$vmhostGet = (ConvertFrom-Json $vmhostGetReq.Content).value
$vmhostGet

function Get-VMHostREST {

    <#  
    .SYNOPSIS  
        Collects VMHost Information from vCenter's RESTful API
    .DESCRIPTION 
        Will inventory all of the VMHosts from vCenter's RESTful API
    .NOTES  
        Author:  Kyle Ruddy, @kmruddy, thatcouldbeaproblem.com
    .PARAMETER vCenter
        The FQDN or IP of your vCenter Server
    .PARAMETER Username
        The username to connect with.
    .PARAMETER Password
        The password to connect with
    .PARAMETER Credential
        The PSCredential object to connect with
    .EXAMPLE
        PS> Get-VMHostREST -vCenter vCenter.fqdn -Username admin -Password password
    #>

    [CmdletBinding()] 
	param(
		[Parameter(Mandatory=$true,Position=0)]
		[String]$vCenter,
		[Parameter(Mandatory=$false,Position=1)]
		[String]$Username,
		[Parameter(Mandatory=$false,Position=2)]
        [String]$Password,
        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential
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
            if ($Username -and $Password) {
                $auth = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Username + ":" + $Password))
            }
            elseif ($Credential) {
                $auth = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Credential.UserName + ':' + $Credential.GetNetworkCredential().Password))                
            }
            else {
                Write-Warning "No authentication parameters found."
            }

            $head = @{
                'Authorization' = "Basic $auth"
            }

            # Authentication - Login 
            $authReq = Invoke-WebRequest -Uri "https://$vCenter/rest/com/vmware/cis/session" -Method Post -Headers $head
            $token = (ConvertFrom-Json $authReq.Content).value
            $session = @{'vmware-api-session-id' = $token}

            $vmhostGetReq = Invoke-WebRequest -Uri "https://$vCenter/rest/vcenter/host" -Method Get -Headers $session
            $vmhostGet = (ConvertFrom-Json $vmhostGetReq.Content).value
            return $vmhostGet

    }

}


