#requires -version 2.0

function Install-AllUpdates {
<#
.Synopsis
   Installs all available, non-hidden updates updates (including optional ones),
   rebooting as necessary. You SHOULD NOT be running this function/cmdlet manually.
    Run the Install-AllUpdates.ps1 script instead.

.PARAMETER ScriptName
    The script name. You SHOULD NOT be providing this parameter manually.
    Run Install-AllUpdates.ps1 which handles this for you.

.PARAMETER ScriptPath
    The script path. You SHOULD NOT be providing this parameter manually.
    Run Install-AllUpdates.ps1 which handles this for you.

.PARAMETER ScriptFullName
    The script full path. You SHOULD NOT be providing this parameter manually.
    Run Install-AllUpdates.ps1 which handles this for you. 
    
.NOTES 
    flowchart: http://i.imgur.com/NSV8AH2.png
#>

    
    [CmdletBinding()]
    Param(
         [Parameter(Mandatory=$true,Position=0,
        HelpMessage="Kill this with ctrl-c and run Install-AllUpdates.ps1")]
        [string]$DontRunThisCmdletManually,
        [Parameter(Mandatory=$true,Position=1,
        HelpMessage="Kill this with ctrl-c and run Install-AllUpdates.ps1")]
        [string]$ScriptName,
        [Parameter(Mandatory=$true,Position=2,
        HelpMessage="Kill this with ctrl-c and run Install-AllUpdates.ps1")]
        [string]$ScriptPath,
        [Parameter(Mandatory=$true,Position=3,HelpMessage="Kill this with ctrl-c and run Install-AllUpdates.ps1")]
        [string]$ScriptFullName
    )

    Begin{
        If ($DontRunThisCmdletManually -NE "PermissionGranted") {
            Write-Host -ForegroundColor Red "You SHOULD NOT be running this function/cmdlet manually.
            Run the Install-AllUpdates.ps1 script instead."
            break}
    }
    Process 
    {
        $Logfile = "$env:PUBLIC\Desktop\PSWU.log"
        Write-Log $Logfile " -=-=-=-=-=-=-=-=-=-=-=-"
        Write-Log $Logfile "PSWU system patcher is starting (as $env:username)."

        Write-Log $Logfile "Starting PSWU function 'Install-AllUpdates'"
        if (!(Test-AdminPrivs)) {
            Write-Warning "You must elevate to Admin privs to download or install updates"
            Write-Log $Logfile "You must elevate to Admin privs to download or install updates"
            break 
        }

        if (Test-RebootNeeded) {
            Write-Log $Logfile "Restart needed (for pending Windows Updates)."
            if (!(CheckForScheduledTask "PSWU")) {ScheduleRerunTask "PSWU" $ScriptFullPath}
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
            $ISearchResult | Hide-Update -KBID 2483139 #hide Language Packs
            $NonHiddenUpdateCount = ($ISearchResult.Updates | Where-Object {$_.IsHidden -eq $false}).Count
            #if ($ISearchResult.Updates.Count -gt 0) {
            if ($NonHiddenUpdateCount -gt 0) {
                Write-Log $Logfile "Non-hidden updates: $NonHiddenUpdateCount"
                [string]$UpdateReport = Show-UpdateList -ISearchResult $ISearchResult
                Write-Log $Logfile $UpdateReport  
                Write-Log $Logfile "Downloading and installing $NonHiddenUpdateCount updates."
                $Install = Install-Update -ISearchResult $ISearchResult -Verbose
                Write-Log $Logfile "Done installing updates. Restarting script to check for more."
                Install-AllUpdates -DontRunThisCmdletManually "PermissionGranted" `
                    -ScriptName $ScriptName `
                    -Scriptpath $ScriptPath `
                    -ScriptFullName $ScriptFullPath `
                    -Verbose
            } else {
                Write-Log $Logfile "Windows is up to date; script cleaning up."
                #check for PSWU Scheduled Task and delete if found
                #use schtasks for win7 compat
                if (CheckForScheduledTask "PSWU") {
                    Write-Log $Logfile "Found PSWU task; removing. "
                    schtasks /delete /tn pswu /F
                    }   
                Write-Log $Logfile "Cleanup complete. Running as $env:username - script exiting."
                Rename-Item -Path $Logfile -NewName "PSWU DONE.log" -Force
                break
            }
        }
    }
    End{}
}

Function Write-Log {
<#
.Synopsis
   Logs short statements, with timestamps, to file defined by $Logfile
.EXAMPLE
   Write-Log c:\logs\logfile.txt "this is a log entry"
#>
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

Function Format-Error {
<#
.Synopsis
    Shortened version of Will Steele's technique 
    as found in Powershell Deep Dives, chapter 11
    http://goo.gl/JQQz0R for his original code.
#>
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

function Test-AdminPrivs () {
<#
.Synopsis
    Test whether currently running with Administrator privs
    I used the technique found here: http://goo.gl/TwmIIf ... modified for readability
	TODO: But what about non-english systems? http://goo.gl/nRIoON and http://goo.gl/O1qh37
#>
    [bool]$retval = $false
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent() 
    $principal = new-object System.Security.Principal.WindowsPrincipal($identity) 
    $admin = [System.Security.Principal.WindowsBuiltInRole]::Administrator 
    $HasRights = $principal.IsInRole($admin)    
    if ($HasRights) {$retval = $true} 
    return $retval
}

function Test-RebootNeeded {
<#
.Synopsis
   Checks whether reboot is needed due to Windows Updates. Returns $true or $false

.Note
    Thanks to Brian Wilhite who documented several of these check methods at
    http://goo.gl/JKZZY and http://goo.gl/OJLSib
.EXAMPLE
   Test-RebootNeeded
#>
    [CmdletBinding()]
    [OutputType([bool])]
    Param()

    Process
    {
        $NeedsReboot = $false
        #Windows Update
        $SystemInfo= New-Object -ComObject "Microsoft.Update.SystemInfo"
        if ($SystemInfo.RebootRequired) {$NeedsReboot = $true}
        #Component Based Servicing
        $CBSRegkey = get-item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing"
        if ($CBSRegkey.Property -contains "RebootRequired") {$NeedsReboot = $true}
        #Pending File Rename Operations
        $PFRORegkey = get-item "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\FileRenameOperations"
        if ($PFRORegkey.Property) {$NeedsReboot = $true}
        $NeedsReboot
    }
}

function ScheduleRerunTask ($TaskName, $ScriptPath) {
<#
.Synopsis
    Creates a Scheduled Task that restarts this script after reboot.
    Tthe *ScheduledTask* cmdlets are PS v3 and up;
    schtasks preserves compat with v2 (win7, 2008r2)
#>
    #note the funky escaping because of http://goo.gl/SgSLrQ
    [string]$TR = """$PSHome\powershell.exe "
    $TR += " -ExecutionPolicy Unrestricted -File \`"$ScriptPath\`" "
    [string]$sctask = "schtasks /create /RU system "
    $sctask += "/SC onstart /TN $TaskName "
    $sctask += "/RL HIGHEST /TR $TR"""
    cmd /c $sctask
}

function CheckForScheduledTask ($TaskName) {
<#
.Synopsis
    Checks to see if the specified scheduled task exists.
#>
    $return = $true
    #Don't need any error output from Powershell
    $ErrorActionPreference = "SilentlyContinue"
    $output = schtasks /query /tn $TaskName   
    if ($LASTEXITCODE -ne 0) {$return = $false}
    $ErrorActionPreference = "Continue"
    $return
}

function Hide-Update {
<#
.Synopsis
   Hides or un-hides updates as specified by KB article number (KBID).
.PARAMETER ISearchResult
   ISearchResult is delivered from Get-UpdateList and is a COM object.
   (http://goo.gl/pvnUSM)
.PARAMETER KBID
   One or more KBIDs to hide or un-hide.
.PARAMETER UNHIDE
   Switch parameter. If used, the specified KBID(s) will be UN-hidden.
.EXAMPLE
   Yo dawg, I herd u liek snover shells.
#>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$false,ValueFromPipeline=$true,Position=0)]$ISearchResult,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$false,Position=1)][string[]]$KBID,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$false,Position=2)][switch]$UnHide
    )

    Process
    {
        if ($ISearchResult -eq $null) {$ISearchResult = Get-UpdateList}
        if ($ISearchResult.pstypenames -notcontains 'System.__ComObject#{d40cff62-e08c-4498-941a-01e25f0fd33c}') {
            Write-Error "$ISearchResult is not an ISearchResult object (http://goo.gl/pvnUSM)"
            break
        }
        foreach ($u in $ISearchResult.Updates){
            if ($UnHide) {
                if ($KBID -contains $($u.KbArticleIDs)) {$u.isHidden = $false}
            } else {
                if ($KBID -contains $($u.KbArticleIDs)) {$u.isHidden = $true}
            }
        }
        $ISearchResult
    }
}

function Get-UpdateList {
<#
.SYNOPSIS
Gets list of updates from Windows Update.

.DESCRIPTION
By default, output is columnized as shown in example 1.
The abbreviated column headers are:

 I T H D R E MB
 | | | | | |  |- Maximum download size, in megabytes
 | | | | | |---- "E" if EULA accepted, "-" if not
 | | | | |------ "R" if reboot required, "-" if not (frequently wrong!)
 | | | |-------- "D" if the update has been downloaded, "-" if not
 | | |---------- "H" if the update is hiden, "-" if not
 | |------------ "S" if software, "D" if driver
 |-------------- "I" if installed, "-" if not

.PARAMETER Computername
The target computer. 
Cannot use an array of computernames here.
Defaults to the local PC.
   
.PARAMETER  Criteria
The search criteria, see http://goo.gl/7nZSPs
Left at default, it will return all software updates that have not yet
been installed. Driver updates are ignored, but Hidden updates are shown
with the "H" flag set.

.NOTES
Returns an IUpdateCollection (http://goo.gl/8C2dbb) named IUpdateCollection
IUpdateCollection is type System.__ComObject#{c1c2f21a-d2f4-4902-b5c6-8a081c19a890}
WU error codes: http://goo.gl/cSWDY8

.EXAMPLE
Get-UpdateList 

KB      T H D R E MB Severity  Published  Title                                                                                               
--      - - - - - -- --------  ---------  -----                                                                                               
3107998 S - - - E 2            11/10/2015 Update for Windows Server 2012 R2 (KB3107998)                                                       
3081320 S - - - E 4  Important 11/10/2015 Security Update for Windows Server 2012 R2 (KB3081320)                                              
3101246 S - - - E 1  Important 11/10/2015 Security Update for Windows Server 2012 R2 (KB3101246)                                              
3102939 S - - - E 2  Important 11/10/2015 Security Update for Windows Server 2012 R2 (KB3102939)                                              
3092601 S - - - E 0  Important 11/10/2015 Security Update for Windows Server 2012 R2 (KB3092601)

.EXAMPLE
(Get-UpdateList).Count
5

Shows that there are 40 updates available.

#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, ValueFromPipeline=$false, Position=0)] $Computername = ".",
        [Parameter(Mandatory=$false, ValueFromPipeline=$false, Position=1)] $Criteria = "IsInstalled=0 and Type='Software'"
    )

    if (($Computername -ne ".") -and ($Computername -ne $env:COMPUTERNAME) -and ($Computername -ne "localhost") ) {
        #following line thanks to http://serverfault.com/a/407379/3437 ... icnivad, you rock!
        #Causes this function to be invoked remotely on the target PC, where the ELSE condition will be true.
        Invoke-Command -ComputerName $Computername -ScriptBlock ${function:Get-UpdateList} -ArgumentList $Computername,$Criteria
    } else {
        $Searcher = New-Object -ComObject Microsoft.Update.Searcher
        $Searcher.Online = $false #try an offline search!
        $ISearchResult = $Searcher.Search($Criteria)
        $ISearchResult.Updates
    }    
}

function Install-Update {
<#
.SYNOPSIS
    Downloads and installs updates

.NOTES
    Uses IUpdateDownloader http://goo.gl/hPK49j
    and IUpdateInstaller http://goo.gl/jeDijU
    WU error codes: http://goo.gl/cSWDY8
#>

    [CmdletBinding()]
    Param (
        [parameter(Mandatory=$false, ValueFromPipeline=$true,Position=0)]$Computername = ".",
        [parameter(Mandatory=$false, ValueFromPipeline=$true,Position=1)]$IUpdateCollection,
        [parameter(Mandatory=$false, ValueFromPipeline=$true,Position=2)][switch]$OneByOne
        )
    <#
        This is working well locally. But FAILS remotely, because the IUpdateCollection is a deserialized object
        and it does not have the AcceptEULA method. Attionally, $DesiredUpdates.Add($u) fails with "Specified cast is not valid."

        Moving Get-UpdateList into the ELSE clause will not work, because the remote system is not guaranteed to have the
        function/cmdlet.

        Worst case? Replicate the code of Get-UpdateList in the ELSE clause (wrapped in its own IF statement)
        Remember, whatever solution is used here will also be needed in Hide-Update.

        Can I populate a variable on the remote machine?
    #>

    if ($IUpdateCollection -eq $null) {$IUpdateCollection = Get-UpdateList $Computername}
    if (($Computername -ne ".") -and ($Computername -ne $env:COMPUTERNAME) -and ($Computername -ne "localhost") ) {
        #following line thanks to http://serverfault.com/a/407379/3437 ... icnivad, you rock!
        #Causes this function to be invoked remotely on the target PC, where the ELSE condition will be true.
        Invoke-Command -ComputerName $Computername -ScriptBlock ${function:Install-Update} -ArgumentList $Computername,$IUpdateCollection,$OneByOne
    } else {
        $DesiredUpdates = New-Object -ComObject Microsoft.Update.UpdateColl
        $counter = 0
        foreach ($u in $IUpdateCollection) {
            $u.AcceptEula() 
            if (!$($u.IsHidden)) { 
                $counter++
                $DesiredUpdates.Add($u) |out-null 
            }
            #Used for debugging. One update at a time.
            if ($OneByOne) { 
                if ($counter -gt 1) {break}
            }      
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
                    3 {Write-Verbose "Installed updates with errors."}
                    default {Write-Error "Installer error $($InstallResult.HResult),resultcode $($InstallResult.ResultCode)"}
                }
            }
        }
    }
}
