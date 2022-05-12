#Requires -Version 5
#Requires -Module VMware.VimAutomation.Core
<#
.SYNOPSIS
    Deploys VCSA within an existing vCenter deployment
.DESCRIPTION
    1. Deploys VCSA from .ova file
    2. Monitors first stage
    3. Invokes and monitors final configuration stage
.EXAMPLE
    # Get host with most available memory
    $VmHost = Get-VMHost | Sort-Object -Property { $_.MemoryTotalMB - $_.MemoryUsageMB } | Select-Object -Last 1

    # Get Datastore with most space available
    $Datastore = $VmHost | Get-Datastore | Sort-Object -Property FreeSpaceGB | Select-Object -Last 1

    $ParamVcsaDeploy = @{
        Server       = 'vCenter01.domain.dev'
        Credential   = (Get-Credential -Message 'Enter vCenter Credentials')
        Path         = '.\VCSA\vcsa\VMware-vCenter-Server-Appliance-7.0.2.00200-17958471_OVF10.ova'
        Name         = 'VCSA_01'
        VmHost       = ($VmHost | Select-Object -ExpandProperty Name)
        Location     = ($VmHost | Get-Cluster | Select-Object -ExpandProperty Name)
        Datastore    = ($Datastore | Select-Object -ExpandProperty Name)
        Ip           = '10.0.0.100'
        PrefixLength = 24            ### Equivelant to a Subnet Mask of 255.255.255.0
        Gateway      = '10.0.0.1'
        DnsServer    = @('10.0.0.5', '10.0.0.6')
        PortGroup    = 'VM Network'
    }

    .\Invoke-VcsaDeployment.ps1 @ParamVcsaDeploy
.OUTPUTS
    Output is json formatted status messages of the deployment
#>
[CmdletBinding()]
param (
    # Vcenter Address to deploy Vcsa in. Deploying a Vcsa ova to an ESX host is not allowed
    [Parameter(Mandatory = $true)]
    [ValidateScript( {
        (Test-NetConnection -ComputerName $_ -Port 443).TcpTestSucceeded
    })]
    [string]
    $Server,

    # Credentials to Vcenter where the Vcsa is being deployed
    [Parameter(Mandatory = $true)]
    [pscredential]
    $Credential,

    # Path to ova file of Vcsa
    [Parameter(Mandatory = $true)]
    [ValidateScript( {
        Test-Path -Path $_
    } )]
    [string]
    $Path,

    # Name of Vcsa VM
    [Parameter(Mandatory = $true)]
    [string]
    $Name,

    # VM Host to deploy Vcsa VM on
    [Parameter(Mandatory = $true)]
    [string]
    $VmHost,

    # Location (Folder, Cluster, Resource Pool) to deploy Vcsa VM
    [Parameter()]
    [string]
    $Location,

    # Datastore to deploy Vcsa VM in
    [Parameter(Mandatory = $true)]
    [string]
    $Datastore,

    # Datastore Provisioning (Defaults to Thin provisioned)
    [Parameter()]
    [ValidateSet('Thin', 'Thick', 'EagerZeroedThick')]
    [string]
    $DiskstorageFormat = 'Thin',

    # Ip Address to deploy Vcsa
    [Parameter(Mandatory = $true)]
    [string]
    $Ip,

    # Prefix length of subnet.  Subnet masks are not accepted.  A subnet mask of 255.255.255.0 is a prefix length of 24
    [Parameter(Mandatory = $true)]
    [ValidateRange(8, 32)]
    [int]
    $PrefixLength,

    # Default Gateway of Vcsa
    [Parameter(Mandatory = $true)]
    [string]
    $Gateway,

    # DNS Server(s) of Vcsa
    [Parameter(Mandatory = $true)]
    [string[]]
    $DnsServer,

    # Portgroup to deploy Vcsa in
    [Parameter(Mandatory = $true)]
    [string]
    $PortGroup,

    # Vcsa Credentials (if different than connected Vcenter)
    [Parameter()]
    [pscredential]
    $VcsaCredential,

    # Vcsa Deployment Size.  Defaults to Tiny
    [Parameter()]
    [ValidateSet('Tiny', 'Small', 'Medium', 'Large', 'XLarge')]
    [string]
    $DeploymentSize = 'Tiny',

    # Hostname of VCSA deployment.  CAUTION: If DNS lookup of this name fails the deployment will fail.  When in doubt, leave out
    [Parameter()]
    [string]
    $Hostname,

    # DNS Zone.  Leave blank to use DHCP.  CAUTION: If DNS lookup in this zone fails the deployment will fail.  When in doubt, leave out
    [Parameter()]
    [string]
    $DnsZone,

    # Domain Search Path.  Leave blank to use DHCP.  CAUTION: If environment DNS is not properly configured the deployment can fail.  When in doubt, leave out
    [Parameter()]
    [string]
    $DomainSearchPath,

    # Enable CEIP (Customer Experience Improvement Program)
    [Parameter()]
    [switch]
    $Ceip
)

# Define Ovf Configuration Parameters
if (-not $VcsaCredential) {
    $VcsaCredential = $Credential
}
$OvfConfiguration = @{
    'guestinfo.cis.appliance.net.mode'        = 'static'
    'guestinfo.cis.appliance.net.addr'        = $Ip
    'guestinfo.cis.appliance.net.prefix'      = $PrefixLength
    'guestinfo.cis.appliance.net.gateway'     = $Gateway
    'guestinfo.cis.appliance.net.dns.servers' = ($DnsServer -join ',')
    'guestinfo.cis.appliance.net.addr.family' = 'ipv4'
    'guestinfo.cis.appliance.root.passwd'     = $VcsaCredential.GetNetworkCredential().Password
    'guestinfo.cis.vmdir.password'            = $VcsaCredential.GetNetworkCredential().Password
    'guestinfo.cis.hadcs.enabled'             = 'True'
    'IpAssignment.IpProtocol'                 = 'IPv4'
    'NetworkMapping.Network 1'                = $PortGroup
    'DeploymentOption'                        = $DeploymentSize.ToLower()
    
    <# Options defined below based on parameter input
    'guestinfo.cis.ceip_enabled'              = 'False'
    'guestinfo.cis.appliance.net.pnid'        = $Config.Vcenter.Name
    'vami.domain.VMware-vCenter-Server-Appliance'     = $Config.DnsZone
    'vami.searchpath.VMware-vCenter-Server-Appliance' = $null
    #>
    
    <# These options exist in the .ova file, but are not mandatory
    'guestinfo.cis.vpxd.ha.management.user'           = $null
    'guestinfo.cis.vpxd.ha.placement'                 = $null
    'guestinfo.cis.vpxd.ha.management.thumbprint'     = $null
    'guestinfo.cis.vpxd.ha.management.port'           = $null
    'guestinfo.cis.vpxd.ha.management.password'       = $null
    'guestinfo.cis.vpxd.ha.management.addr'           = $null
    #>
}

switch ($PSBoundParameters.Keys) {
    'Ceip' { $OvfConfiguration.'guestinfo.cis.ceip_enabled' = 'True' }
    'Hostname' { $OvfConfiguration.'guestinfo.cis.appliance.net.pnid' = $Hostname }
    'DnsZone' { $OvfConfiguration.'vami.domain.VMware-vCenter-Server-Appliance' = $DnsZone }
    'DomainSearchPath' { $OvfConfiguration.'vami.searchpath.VMware-vCenter-Server-Appliance' = $DomainSearchPath }
}

# Configure variables inside job scope
$RootVcenter = Connect-VIServer -Force -Server $Server -Credential $Credential
$VmHost = Get-VMHost -Server $RootVcenter -Name $VmHost

$ParamOvfDeployment = @{
    'Server'            = $RootVcenter
    'Source'            = $Path
    'Name'              = $Name
    'Location'          = $Location
    'VMHost'            = $VmHost
    'Datastore'         = $Datastore
    'DiskstorageFormat' = $DiskstorageFormat
    'OvfConfiguration'  = $OvfConfiguration
    'Force'             = $true
}

$ImportVcsaTask = Import-VApp @ParamOvfDeployment

# Start VCSA VM and wait for vmtools to start
Write-Verbose 'Starting VCSA VM and wait for VMTools to start'
$VcsaVm = Get-VM -Server $RootVcenter -Name $Name
Start-VM -Server $RootVcenter -VM $VcsaVm -Confirm:$false
Wait-Tools -Server $RootVcenter -VM $VcsaVm

# Setup connection to deployed Vcsa Rest API
$VcsaBaseUri = 'https://{0}:5480/rest' -f $Ip
$CredentialCombination = '{0}:{1}' -f 'root', $VcsaCredential.GetNetworkCredential().Password
$Base64Cred = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($CredentialCombination))

$Headers = @{
    'Authorization' = "Basic $Base64Cred"
    'Content-Type'  = 'application/json'
}

$ParamIrmCommon = @{
    'ContentType' = 'application/json'
    'Headers'     = $Headers
}

# Ignore Certificate Issues
if ($PSVersionTable.PSVersion.Major -ge 6 ) {
    $ParamIrmCommon.SkipCertificateCheck = $true
}
else {
    Add-Type @"
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
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
}

# Monitor Stage 1 Initialization until completed
Write-Verbose 'Start Initialization Monitor'
$Count = 0
$ConfigWatch = @( )

do {
    $ConfigStatus = Invoke-RestMethod @ParamIrmCommon -Method Get -Uri "$VcsaBaseUri/vcenter/deployment"
    Write-Output $ConfigStatus
    $ConfigWatch += @{
        Count    = $Count
        DateTime = (Get-Date -Format 'yyyy.MM.ddTHH.mm.ss')
        Status   = $ConfigStatus
    }
    $Count += 1
    Start-Sleep -Seconds 30
} until ($ConfigStatus.state -eq 'INITIALIZED')

Write-Output ($ConfigStatus | ConvertTo-Json -Depth 6)
Write-Output 'Starting Stage 2 Configuration'

$VcenterDeployBody = @{
    spec = @{
        auto_answer   = $true
        vcsa_embedded = @{
            ceip_enabled = $Ceip
            standalone   = @{
                sso_admin_password = $VcsaCredential.GetNetworkCredential().Password
                sso_domain_name    = 'vsphere.local'
            }
        }
    }
}

$StartVcenterInstall = Invoke-RestMethod @ParamIrmCommon -Method Post -Uri "$VcsaBaseUri/vcenter/deployment/install?action=start" -Body ($VcenterDeployBody | ConvertTo-Json -Depth 6)
Write-Verbose 'Starting Deployment Monitor'

do {
    $ConfigStatus = Invoke-RestMethod @ParamIrmCommon -Method Get -Uri "$VcsaBaseUri/vcenter/deployment"
    Write-Output $ConfigStatus
    $ConfigWatch += @{
        Count    = $Count
        DateTime = (Get-Date -Format 'yyyy.MM.ddTHH.mm.ss')
        Status   = $ConfigStatus
    }
    $Count += 1
    Start-Sleep -Seconds 30
} until ($ConfigStatus.state -eq 'CONFIGURED')

Write-Output ($ConfigStatus | ConvertTo-Json -Depth 6)
Write-Output 'Deployment Completed. See results above'