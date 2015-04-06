<#
.Synopsis
 Checks Windows Update Agent and reports current installed version

.PARAMETER Param1
 Help for Param1
.EXAMPLE
 Example of how to use this cmdlet
.EXAMPLE
 Another example of how to use this cmdlet
#>
function Get-WUInstalledVersion
{
    [CmdletBinding()]
    Param
    (
        #[Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true, Position=0)][string]$Param1
    )

    Begin{}
    Process
    {
        $AgentInfo = New-Object -ComObject Microsoft.Update.AgentInfo
        #$AgentInfo.GetInfo('ApiMajorVersion')
        #$AgentInfo.GetInfo('ApiMinorVersion')
        $WUInstalledVersion = $AgentInfo.GetInfo('ProductVersionString')
        $WUInstalledVersion
    }
    End{}
}

<#
.Synopsis
 Downloads WURedist.cab and reports newest available WU version and download URL

.PARAMETER Param1
 Help for Param1
.EXAMPLE
 Example of how to use this cmdlet
.EXAMPLE
 Another example of how to use this cmdlet
#>
function Get-WUAvailableVersion
{
    [CmdletBinding()]
    Param
    (
        #[Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true, Position=0)][string]$Param1
    )

    Begin{}
    Process
    {
        $downloadfolder = "$env:userprofile\Downloads"
        $webclient = New-Object System.Net.WebClient
        $dlfile = "http://update.microsoft.com/redist/wuredist.cab"
        $webclient.downloadfile($dlfile,"$downloadfolder\wuredist.cab")
        $result = New-Object -TypeName PSObject 
        if ((Get-AuthenticodeSignature "$downloadfolder\wuredist.cab").Status -eq "Valid") {
            $eatme = expand "$downloadfolder\wuredist.cab" "$downloadfolder\wuredist.xml" 
            [xml]$wuredist = get-content $downloadfolder\wuredist.xml
            $OSArch = "x"
            $OSArch += ((Get-WmiObject win32_operatingsystem).OSArchitecture -split("-"))[0]
            $wulatestversion = $($wuredist.WURedist.StandaloneRedist.architecture | where { $_.name -match $OSArch}).clientversion
            $wudownload = $($wuredist.WURedist.StandaloneRedist.architecture | where { $_.name -match $OSArch}).downloadurl 
            $result | Add-Member NoteProperty Version $wulatestversion
            $result | Add-Member NoteProperty DownloadUrl $wudownload
            $result
        } else { 
            $result | Add-Member NoteProperty Version "ERROR"
            $result | Add-Member NoteProperty DownloadUrl "ERROR"
            $result
        }
    }
    End{}
}

<#
.Synopsis
   Get the WU redistributable
.DESCRIPTION
   Long description
.PARAMETER Param1
Help for Param1
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Get-WUcab
{
    [CmdletBinding()]
    [OutputType([int])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true, Position=0)][string]$Param1      

    )

    Begin{}
    Process
    {
        $downloadfolder = "$env:userprofile\Downloads"
        $webclient = New-Object System.Net.WebClient
        $dlfile = "http://update.microsoft.com/redist/wuredist.cab"
        $webclient.downloadfile($dlfile,"$downloadfolder\wuredist.cab")
        if ((Get-AuthenticodeSignature "$downloadfolder\wuredist.cab").Status -eq "Valid") {Write-Host "ok"}
        expand "$downloadfolder\wuredist.cab" "$downloadfolder\wuredist.xml" 
        [xml]$wuredist = get-content $downloadfolder\wuredist.xml
        $OSArch = "x"
        $OSArch += ((Get-WmiObject win32_operatingsystem).OSArchitecture -split("-"))[0]
        $wulatestversion = $($wuredist.WURedist.StandaloneRedist.architecture | where { $_.name -match $OSArch}).clientversion
        $wudownload = $($wuredist.WURedist.StandaloneRedist.architecture | where { $_.name -match $OSArch}).downloadurl
        $urlarray = @()
        $urlarray = $wudownload -split("/")
        $dlfile = "$downloadfolder\$($urlarray[-1])"
        $wulatestversion
        $wudownload
        $dlfile
        $webclient.downloadfile($wudownload,"$dlfile")
        if ($psversiontable.PSVersion.ToString() -gt 2) {unblock-file "$dlfile"}
        start-process "$dlfile"
    }
    End{}
}

$WUAvailable = Get-WUAvailableVersion
Write-Output "Installed WUA version: $(Get-WUInstalledVersion) .. Available WUA version: $($WUAvailable.version)  "
