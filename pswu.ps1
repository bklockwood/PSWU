<#
Using the technique described at http://goo.gl/l6Gtus to put program logic at top, functions below.
20150306 - 4AM
#>
#requires -version 3.0
function Main {
    #The MAIN function's job is to be basic script logic, log progress and issues, interact with user.
    #flowchart: http://i.imgur.com/NSV8AH2.png

    
    
    Write-Log $Logfile "Starting function 'Main'"
    if (!(Test-AdminPrivs)) {
        Write-Warning "You must elevate to Admin privs to download or install updates"
        Write-Log $Logfile "You must elevate to Admin privs to download or install updates"
        break 
    }

    if (Test-RebootNeeded) {
        Write-Log $Logfile "Restart needed (for pending Windows Updates)."
        ScheduleRerunTask "PSWU"
        Write-Log $Logfile "Restarting in 15 seconds!"
        Start-Sleep -Seconds 15
        Restart-Computer -Force
        break #Without this, script will continue processing during the shutdown.
    } else {
        Write-Log $Logfile "No reboot needed."
    }

    Write-Log $Logfile "Checking for updates."
    $ISearchResult = Get-UpdateList

    if ($ISearchResult.ResultCode -eq 2) {
        Write-Log $Logfile "Successfully retreived update list"
        if ($ISearchResult.Updates.Count -gt 0) {
            [string]$UpdateReport = Show-UpdateList -ISearchResult $ISearchResult
            Write-Log $Logfile $UpdateReport  
            Write-Log $Logfile "Downloading and installing $($ISearchResult.Updates.Count) updates."
            $Install = Install-Update -ISearchResult $ISearchResult
            Write-Log $Logfile "Done installing updates. Restarting script to check for more."
            Main
        } else {
            Write-Log $Logfile "Windows is up to date; script cleaning up."
            #check for PSWU Scheduled Task and delete if found
           if (Get-ScheduledTask -TaskName "PSWU" -ErrorAction Ignore) {
                Write-Log $Logfile "Found PSWU task; removing. "
                #Tried Stop-SceduledTask and Unregister-ScheduledTask
                #Nither will kill the running task. schtasks works.
                schtasks /delete /tn pswu /F
                }
		    #TODO: tell user all done. write to all-users desktop?     
            Write-Log $Logfile "Cleanup complete. Running as $env:username - script exiting."
            New-Item -ItemType File -Path "$env:PUBLIC\Desktop" -Name "DONE UPDATING" -Value "You can delete this file and $Logfile"
            break
        }
    }
}


<#
.Synopsis
   Logs short statements, with timestamps, to file defined by $Logfile
.EXAMPLE
   Write-Log c:\logs\logfile.txt "this is a log entry"
#>
Function Write-Log
{
   Param 
   (
   [Parameter(Mandatory=$true,Position=0)][string]$Logfile,
   [Parameter(Mandatory=$true,Position=1)][string]$LogString   
   )

   #dotNET datestamp formats http://goo.gl/YkkEXa and http://goo.gl/B5JhW
   $Logtext = "$(get-date -Format yyyyMMdd-HH:mm:ss) $LogString"
   Out-file -FilePath $Logfile -Append -NoClobber -InputObject $Logtext -Encoding ascii
   #Write-Host intentional here! $Logtext must *not* go into pipeline.
   Write-Host $Logtext
}

<#
.Synopsis
    Shortened version of Will Steele's technique 
    as found in Powershell Deep Dives, chapter 11
    http://goo.gl/JQQz0R for his original code.
#>
Function Format-Error 
{
    #Param ([Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)] $MyError)

    $timestamp = Get-Date -Format 'yyyyMMdd HH:mm:ss'

@"
----ERROR in $($_.InvocationInfo.ScriptName).----
$timestamp  Error Details: $($_)
$timestamp  Line: $($_.InvocationInfo.Line)
$timestamp  Line Number: $($_.InvocationInfo.ScriptLineNumber) Offset: $($_.InvocationInfo.OffsetInLine)
$timestamp  Command: $($_.InvocationInfo.MyCommand)
"@
}

<#
.Synopsis
    Test whether currently running with Administrator privs
    I used the technique found here: http://goo.gl/TwmIIf ... modified for readability
	TODO: But what about non-english systems? http://goo.gl/nRIoON and http://goo.gl/O1qh37
#>
function Test-AdminPrivs () 
{
    [bool]$retval = $false
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent() 
    $principal = new-object System.Security.Principal.WindowsPrincipal($identity) 
    $admin = [System.Security.Principal.WindowsBuiltInRole]::Administrator 
    $HasRights = $principal.IsInRole($admin)    
    if ($HasRights) {$retval = $true} 
    return $retval
}

<#
.Synopsis
   Checks whether reboot is needed due to Windows Updates. Returns $true or $false

   TODO test for other reboot conditions.
.EXAMPLE
   Test-RebootNeeded
#>
function Test-RebootNeeded 
{
    [CmdletBinding()]
    [OutputType([bool])]
    Param()

    Begin{}
    Process
    {
        $SystemInfo= New-Object -ComObject "Microsoft.Update.SystemInfo"
        <#if ($($SystemInfo.RebootRequired)) {
            Return $true
        }else{
            Return $false
        }#>
        $SystemInfo.RebootRequired
    }
    End{}
}

<#
.Synopsis
    Creates a Scheduled Task that restarts this script after reboot.
#>
function ScheduleRerunTask ($TaskName)
{
    $Action = New-ScheduledTaskAction -Execute "$PSHome\powershell.exe" -Argument "-executionPolicy Unrestricted -File $ScriptPath"
    $Trigger = New-ScheduledTaskTrigger -AtStartup
    $User = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $Settings = New-ScheduledTaskSettingsSet
    $Task = New-ScheduledTask -Action $Action -Principal $User -Trigger $Trigger -Settings $Settings
    Register-ScheduledTask -TaskName $TaskName -InputObject $Task
}

<#
.Synopsis
Gets list of updates from Windows Update.
.DESCRIPTION
   
.PARAMETER Criteria
The search criteria, see http://goo.gl/7nZSPs
Left at default, it will return all updates that have not yet
been installed, whether software or driver. Including Hidden
updates.

.NOTES
Returns an ISearchResult object (http://goo.gl/pvnUSM) named $ISearchResult
ISearchresult type - System.__ComObject#{d40cff62-e08c-4498-941a-01e25f0fd33c}
$ISearchResult.Updates contains an IUpdateCollection  - http://goo.gl/8C2dbb
WU error codes: http://goo.gl/cSWDY8

.EXAMPLE
Get-UpdateList | ft -AutoSize

ResultCode RootCategories     Updates            Warnings          
---------- --------------     -------            --------          
         2 System.__ComObject System.__ComObject System.__ComObject

.EXAMPLE
(Get-UpdateList).Updates.Count
40

Shows that there are 40 updates available.

.EXAMPLE
(Get-UpdateList).Updates | select maxdownloadsize, title | ft -AutoSize

MaxDownloadSize Title                                                                                                                
--------------- -----                                                                                                                
       10123467 Update for Windows Server 2012 R2 (KB2884846)                                                                        
         948931 Security Update for Windows Server 2012 R2 (KB2876331)                                                               
         517819 Security Update for Windows Server 2012 R2 (KB2892074)                                                               
         376647 Update for Windows Server 2012 R2 (KB2917993)
#>
function Get-UpdateList
{
    [CmdletBinding()]
    Param
    ([Parameter(Mandatory=$false, ValueFromPipeline=$false, Position=0)] $Criteria = "IsInstalled=0")

    try {
        $Searcher = New-Object -ComObject Microsoft.Update.Searcher
        $ISearchResult = $Searcher.Search($Criteria)
        $ISearchResult
    } catch {
        Write-Error "ERROR in Get-UpdateList"
        return $_
    } 
    
}

<#
.Synopsis
 Print a nice table of Updates not installed with some attribute info.

.Description
 Columns:
 
 THDRE
 |||||- "E" if EULA accepted, "-" if not
 ||||-- "R" if reboot required, "-" if not (frequently wrong!)
 |||--- "D" if the update has been downloaded, "-" if not
 ||---- "H" if the update is hiden, "-" if not
 |----- "S" if software, "D" if driver

.TODO
They don't sort properly;
#>
Function Show-UpdateList 
{
    [Cmdletbinding()]
    Param([Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)] $ISearchResult)
    if ($ISearchResult.pstypenames -notcontains 'System.__ComObject#{d40cff62-e08c-4498-941a-01e25f0fd33c}') {
        Write-Error "$ISearchResult is not an ISearchResult object (http://goo.gl/pvnUSM)"
        break
    }
    Write-Output "$($ISearchResult.Updates.Count) updates available:"
    $ISearchResult.Updates |
    Select @{n='KB';e={$_.KbArticleIds[-1]}},
        #Update type 1 is software, type 2 is driver. http://goo.gl/VvV7tt
        @{n='T';e={if ($_.Type -eq 1) {"S"} ElseIf ($_.Type -eq 2) {"D"}}},
        @{n='H';e={if ($_.isHidden) {"H"} Else {"-"}}},
        @{n='D';e={if ($_.isDownloaded) {"D"} Else {"-"}}},
        @{n='R';e={if ($_.Rebootrequired) {"R"} Else {"-"}}},
        @{n='E';e={if ($_.EulaAccepted) {"E"} Else {"-"}}},
        @{n='MB';e={'{0:N0}' -f ($_.MaxDownloadSize/1MB)}},            
        @{n='Severity';e={$_.MsrcSeverity}},
        @{n='Published';e={$_.LastDeploymentChangeTime.ToShortDateString()}},
        #@{n='UID';e={$_.Identity.UpdateID}}, 
        #truncate title to 40 chars       
        @{n='Title';e={ if ($($_.Title.Length) -lt 40) {$_.Title} else {$($_.Title.Substring(0,37)) + "..."}}} |
    Sort -Property $_.LastDeploymentChangeTime | ft -AutoSize |out-string 
 
}

<#
.SYNOPSIS
    Downloads and installs updates

.NOTES
    Uses IUpdateDownloader http://goo.gl/hPK49j
    and IUpdateInstaller http://goo.gl/jeDijU
    WU error codes: http://goo.gl/cSWDY8
#>
function Install-Update 
{
    [CmdletBinding()]
    Param ([parameter(Mandatory=$true, ValueFromPipeline=$true)]$ISearchResult)    
    if ($ISearchResult.pstypenames -notcontains 'System.__ComObject#{d40cff62-e08c-4498-941a-01e25f0fd33c}') {
        Write-Error "$ISearchResult is not an ISearchResult object (http://goo.gl/pvnUSM)"
        break
    }

    $DesiredUpdates = New-Object -ComObject Microsoft.Update.UpdateColl
    foreach ($u in $ISearchResult.Updates) {
        $u.AcceptEula() 
        if (!$($u.IsHidden)) { $DesiredUpdates.Add($u) |out-null }        
    }

    If ($DesiredUpdates.Count -lt 1) { 
        Write-Verbose "No updates to install!"
    } else {
        Write-Verbose "Downloading and installing $($DesiredUpdates.Count) updates" 
        $Downloader = New-Object -ComObject Microsoft.Update.Downloader
        $Downloader.Updates = $DesiredUpdates
        $DownloadResult = $Downloader.Download()
        #Resultcode 2-success, 3-success with errors. 
        #Using -contains instead of -in for PS v2 compat
        if (2,3 -notcontains $DownloadResult.ResultCode) {
            Write-Error "Downloader error HResult $($DownloadResult.HResult), resultcode $($DownloadResult.ResultCode)"
        } else {
            if ($DownloadResult.ResultCode -eq 3) {Write-Verbose "Downloaded with errors; beginning install."}
            if ($DownloadResult.ResultCode -eq 2) {Write-Verbose "Downloaded successfully; beginning install."}
            $Installer = New-Object -ComObject Microsoft.Update.Installer
            $Installer.Updates = $DesiredUpdates
            $InstallResult = $Installer.Install()
            switch ($InstallResult.ResultCode) {
                2 {Write-Verbose "Installed updates successfully."}
                3 {Write-Verbose "Installed updates swith errors."}
                default {Write-Error "Installer error $($InstallResult.HResult),resultcode $($InstallResult.ResultCode)"}
            }
        }        
    }
}


[string]$Computer = $env:COMPUTERNAME
[string]$ScriptName = $($MyInvocation.MyCommand.Name)
[string]$ScriptName = $($ScriptName.Split('.')[0])
[string]$ScriptPath = $PSCommandPath


$Logfile = "$env:PUBLIC\Desktop\$ScriptName.log"
Write-Log $Logfile " -=-=-=-=-=-=-=-=-=-=-=-"
Write-Log $Logfile "PSWU system patcher is starting (as $env:username)."

Main
