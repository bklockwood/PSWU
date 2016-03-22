#requires -version 2.0
#Set-StrictMode -Version 2.0

Function Install-AllUpdates {
<#
.SYNOPSIS
Installs all available, non-hidden updates updates, rebooting as many times
as necessary, until there are no more updates to install. 
.PARAMETER SkipOptional
If this switch parameter is given, "Optional" updates will not be installed.
.PARAMETER Driver
If this switch parameter is given, Driver updates (from WU) will be installed in
addition to software updates.
.PARAMETER OnlyDriver
If this switch parameter is given, Driver updates (from WU) will be installed,
software updates will be IGNORED.
.EXAMPLE
Install-AllUpdates 
.NOTES 
flowchart: http://i.imgur.com/NSV8AH2.png
#>
    Param (
       [Parameter(ValueFromPipelineByPropertyName=$true,Position=0)][string]$Computername = ".",
       [Parameter(ValueFromPipelineByPropertyName=$true,Position=1)][switch]$SkipOptional,
       [Parameter(ValueFromPipelineByPropertyName=$true,Position=2)][switch]$Driver,
       [Parameter(ValueFromPipelineByPropertyName=$true,Position=3)][switch]$OnlyDriver   
    )

    if ($Driver -and $OnlyDriver) {
        Write-Warning "Use -Driver *or* -OnlyDriver, not both at once!"
        Write-Warning "Install-AllUpdates terminating."
        break
    }

    [string]$boundparams = Convert-ParamDictToString $PSBoundParameters
    [string]$Command = "&import-module pswu;Install-AllUpdates $boundparams"

    if (($Computername -ne ".") -and ($Computername -ne $env:COMPUTERNAME) -and ($Computername -ne "localhost") ) {
        #this clause runs when a remote machine has been specified 
        Compare-PSWU -Computername $Computername
        $status = "Install-AllUpdates calling New-PSTask. Computername: $Computername Command: $Command"
        Write-Log -EventID 1 -Source Install-AllUpdates -EntryType Information -Message $status
        #TODO need errorchecking here. if the task can't be created, log an error and quit
        New-PSTask -Computername $Computername -TaskName "PSWU Install-AllUpdates (FromRemote)" -Command $Command |Invoke-PSTask
    } else {
        #this clause runs when the script has been invoked targeting local machine        
        $AdminStatus = Test-AdminPrivs
        $RebootStatus = Test-RebootNeeded -Computername $Computername
        $status = "Starting locally with params: $boundparams `r`n"
        $status += "Current conditions: `r`n"
        $status += "User= $env:username; Admin= $AdminStatus; NeedsReboot= $RebootStatus."
        Write-Log -EventID 2 -Source Install-AllUpdates -EntryType Information -Message $status    

        if ($AdminStatus -eq $false) {
            $status = "Exiting. PSWU is not elevated; cannot continue."
            Write-Log -EventID 3 -Source Install-AllUpdates -EntryType Error -Message $status
            break
        }

        if ($RebootStatus -eq $true) {
            $status = "Restart needed. Creating startup task and rebooting."
            Write-Log -EventID 4 -Source Install-AllUpdates -EntryType Information -Message $status
            New-PSTask -ComputerName $env:COMPUTERNAME -TaskName "PSWU Install-AllUpdates (AtBoot)" -Command $Command -RunAtBoot

            $status = "Restart commence NOW"
            Write-Log -EventID 4 -Source Install-AllUpdates -EntryType Information -Message $status
            Restart-Computer -Force
            Start-Sleep -Seconds 10
            $status = "WTF (computer did not restart)"
            Write-Log -EventID 5 -Source Install-AllUpdates -EntryType Error -Message $status
        } 
               
        $UpdateList = Get-UpdateList -SearchObject        
        $DoNotApplyCount = 0
        foreach ($u in $($UpdateList.Updates)) {
            if (($u.isHidden) -or ($SkipOptional -and ($u.BrowseOnly))) {$DoNotApplyCount ++}
        }
        $UpdatesToInstall = $($UpdateList.Updates.Count) - $DoNotApplyCount
            
        if ($UpdatesToInstall -gt 0) {
            Install-Update -ISearchResult $UpdateList @PSBoundParameters

            $status = "Returning to start.`r`n"
            $status += "Sending params: $boundparams"
            Write-Log -EventID 7 -Source Install-AllUpdates -EntryType Information -Message $status
            #Install-AllUpdates -Computername $Computername @PSBoundParameters 
            Install-AllUpdates @PSBoundParameters     
        } else {
            $status = "Removing all PSWU tasks and exiting. No eligible updates found.`r`n"
            if ($DoNotApplyCount -gt 0) {
                $status += "$DoNotApplyCount ineligible updates (hidden, or excluded by params): `r`n $boundparams.`r`n" 
            }
            Write-Log -EventID 8 -Source Install-AllUpdates -EntryType Information -Message $status
            $Scheduler = New-Object -ComObject Schedule.Service
            $Scheduler.Connect($ComputerName)
            if ($Scheduler.Connected) {
                $TaskFolder = $Scheduler.GetFolder("\")
                $Tasks = $TaskFolder.GetTasks(0)
                $Tasks.Count
                foreach ($task in $Tasks) {
                    if ($($task.name).StartsWith("PSWU")) {$TaskFolder.DeleteTask($task.name,0)}
                }
            }            
        }        
    }
}

Function Write-Log {
<#
.SYNOPSIS
Internal non-advanced function for writing to evtnlog named "PSWU".
If the log does not exist, it will be created.
.PARAMETER EventID
A numeric evnt ID.
.PARAMETER EntryType
An event type. Must be "Information", "Error", or "Warning".
If this switch parameter is given, Driver updates (from WU) will be installed in
addition to software updates.
.PARAMETER Source
An event Source. The name of the function that emits the event.
.PARAMETER Message
.EXAMPLE
Write-Log -EventID 21 -EntryType Information -Source Hide-Update -Message $MyMessageString
.NOTES 
flowchart: http://i.imgur.com/NSV8AH2.png
#>
    Param (
       [Parameter(Mandatory=$true,Position=0)][string]$EventID,
       [Parameter(Mandatory=$true,Position=1)]
        [ValidateSet("Information","Error","Warning")][string]$EntryType = "Information",
       [Parameter(Mandatory=$true,Position=2)][string]$Source = "PSWU",
       [Parameter(Mandatory=$true,Position=3)][string]$Message
    )        
    
    #Try to write to eventlog named "PSWU"; if that eventlog is not present, create it and try again.
    [int]$retrycount = 0
    [bool]$success = $false
    
    while (-not $success) { 
        try {
            Write-EventLog -LogName PSWU -Source $source -EventId $EventID -EntryType $EntryType `
                -Message $Message -ErrorAction Stop
            switch ($EntryType) {
                "Information" {Write-Verbose $Message}
                "Error" {Write-Error $Message}
                "Warning" {Write-Warning $Message}
                default {Write-Error "Bad EntryType parameter passed to Write-Log: $EntryType"}
            }
            $success = $true
        } catch {
            $sources = "Test-AdminPrivs","Test-RebootNeeded","Hide-Update","Install-AllUpdates",
                "Get-UpdateHistory","Get-UpdateList","Install-Update","Install-RemotePSWU",
                "New-PSTask","Invoke-PSTask","Convert-UTCtoLocal","PSWU"
            New-EventLog -LogName PSWU -Source $sources -ErrorAction SilentlyContinue
        }

        $retrycount ++
        if ($retrycount -gt 1) {
            Write-Error "Something wrong with event logging."
            break
        }
    }
}

Function Format-Error {
<#
.SYNOPSIS
Shortened version of Will Steele's technique 
as found in Powershell Deep Dives, chapter 11
http://goo.gl/JQQz0R for his original code.
.NOTES
There are no examples for this function; it is not meant to 
be called by humans.
As of 2016/03/12, this function is not called by any other part of PSWU;
it is kept around because *maybe* I will use it later. 
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
.SYNOPSIS
Test whether currently running with Administrator privs.
.DESCRIPTION
Returns TRUE if the calling account has admin privs; FALSE if not.
.NOTES
I used the technique found here: http://goo.gl/TwmIIf ... modified for readability.
TODO: But what about non-english systems? http://goo.gl/nRIoON and http://goo.gl/O1qh37
.EXAMPLE
Test-AdminPrivs
True
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
.SYNOPSIS
Checks whether reboot is needed due to Windows Updates. Returns $true or $false
.PARAMETER Computername
The target computer. Defaults to the local PC.
.NOTES
Thanks to Brian Wilhite who documented several of these check methods at
http://goo.gl/JKZZY and http://goo.gl/OJLSib
.EXAMPLE
Test-RebootNeeded -Computername AaronsPC
#>
    [CmdletBinding()]
    [OutputType([bool])]
    Param([Parameter(ValueFromPipeline=$true, Position=0)] [string]$Computername = ".")

    Write-Verbose "Starting '$($MyInvocation.Line)'."

    if (($Computername -ne ".") -and ($Computername -ne $env:COMPUTERNAME) -and ($Computername -ne "localhost") ) {
        #this clause runs when a remote machine has been specified
        #output variable in scriptblock because #26 https://github.com/bklockwood/PSWU/issues/26 
        Invoke-Command -ComputerName $Computername -ScriptBlock { import-module PSWU; $output = Test-RebootNeeded; $output } 
    } else {
        [bool]$NeedsReboot = $false
        <#
            #Windows Update ISystemInformation, fails remotely, https://goo.gl/Txmf4S
            $SystemInfo= New-Object -ComObject "Microsoft.Update.SystemInfo" 
            if ($SystemInfo.RebootRequired) {$NeedsReboot = $true} 
            #>
        #Windows Update registry key http://goo.gl/GiJCO8
        $WURegKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
        if (test-path $WURegKey) {$NeedsReboot = $true}
        #Component Based Servicing http://goo.gl/GiJCO8
        $CBSRegkey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
        if (test-path $CBSRegkey) {$NeedsReboot = $true}
        #Pending File Rename Operations
        $PFRORegkey = get-item "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\FileRenameOperations"
        if ($PFRORegkey.Property) {$NeedsReboot = $true}
        $NeedsReboot
    }
}

function Hide-Update {
<#
.Synopsis
   Hides or un-hides updates as specified by KB article number (KBID).
.PARAMETER Computername
   The target computer. Defaults to the local PC.
.PARAMETER KBID
   One or more KBIDs to hide or un-hide.
.PARAMETER UNHIDE
   Switch parameter. If used, the specified KBID(s) will be UN-hidden.
.PARAMETER ISearchResult
   ISearchResult is delivered from Get-UpdateList and is a COM object.
   (http://goo.gl/pvnUSM)
.NOTES
   Hiding updates is a protected action which cannot be performed remotely,
   per Microoft: https://goo.gl/Afi70J ... so, when a remote computer is 
   specified, this cmdlet will create a Scheduled Task on the remote 
   system, and wait for its completion.
.EXAMPLE
   Hide-Update -Computername t7 -KBID 2483139 -Verbose
   VERBOSE: Task was created
   VERBOSE: PSWU task started on t7, waiting for completion.
   ...
   VERBOSE: PSWU task on t7 is in READY state.
   VERBOSE: PSWU task on t7 last run state: COMPLETED SUCCESSFULLY
   VERBOSE: Task completed; t7 does NOT need reboot.

   The above example hides the KB2483139 update (Language Packs) on a 
   remote computer named "t7" and produces verbose output.

.EXAMPLE
   Hide-Update -Computername t7 -UnHide -KBID 3012973
   ...
   
   The above example UN-hides KB3012973 (upgrade to Windows 10)
   on a remote computer named "t7". While waiting for the scheduled 
   task to complete, one dot is printed to console every ten seconds.    
#>
    [CmdletBinding()]
    Param
    (
        [Parameter(ValueFromPipeline=$true, Position=0)] [string]$Computername = ".",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$false,Position=1)][string[]]$KBID,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$false,Position=2)][switch]$UnHide,
        [Parameter(Mandatory=$false,ValueFromPipeline=$true,Position=3)]$ISearchResult
    )
    
    if (($Computername -ne ".") -and ($Computername -ne $env:COMPUTERNAME) -and ($Computername -ne "localhost") ) {
        #this clause runs when a remote machine has been specified
        #NOTE: reason for this scheduled task explained at "Hateful Note" in Install-Update
        Compare-PSWU -Computername $Computername
        $KBID = $KBID -Join ","
        if ($UnHide) {
            $command = "&import-module pswu;Hide-Update -UnHide -KBID $KBID"
        } else {
            $command = "&import-module pswu;Hide-Update -KBID $KBID"
        }
        Write-Verbose "Sending a Hide-Update task to $Computername"
        New-PSTask -Computername $Computername -Taskname "PSWU Hide-Update" -Command $command | Invoke-PSTask -Follow

    } else {
        if ($ISearchResult -eq $null) {$ISearchResult = Get-UpdateList -SearchObject}
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
    }
}

function Get-UpdateHistory {
<#
.SYNOPSIS
Gets update history for the target computer.
.PARAMETER Computername
The target computer. Defaults to the local PC.
.EXAMPLE
get-updatehistory t7
01/23/2016 04:09:16, Install, Success, Security Update for Windows 7 for x64-based Systems (KB3108664)
01/23/2016 04:04:09, Install, Success, Security Update for Windows 7 for x64-based Systems (KB3069762)
01/23/2016 04:02:27, Install, Success, Windows Malicious Software Removal Tool x64 - January 2016 (KB890830)
01/23/2016 04:00:50, Install, Success, Update for Windows 7 for x64-based Systems (KB2970228)
01/23/2016 04:00:35, Install, Success, Security Update for Windows 7 for x64-based Systems (KB2965788)
#>
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$true, Position=0)] [string]$Computername = "."
    )

    if (($Computername -ne ".") -and ($Computername -ne $env:COMPUTERNAME) -and ($Computername -ne "localhost") ) {
        Compare-PSWU -Computername $Computername  
        Invoke-Command -ComputerName $Computername -scriptblock {import-module PSWU; $output = Get-UpdateHistory; $output}
    } else {
        $Searcher = New-Object -ComObject Microsoft.Update.Searcher
        #$Searcher.Online = $false #try an offline search!
        $HistoryCount = $Searcher.GetTotalHistoryCount()
        if ($HistoryCount -gt 0) {
            $History = $Searcher.QueryHistory(0, $HistoryCount)            
            foreach ($u in $History) {            
                switch ($($u.Operation)) {
                    1 {$operation = "Install"}
                    2 {$operation = "Uninstall"}
                }
                switch ($($u.ResultCode)) {
                    0 {$resultcode = "NotStarted"}
                    1 {$resultcode = "InProgress"}
                    2 {$resultcode = "Success"}
                    3 {$resultcode = "Success(Errors)"}
                    4 {$resultcode = "Fail"}
                    5 {$resultcode = "Abort"}
                }
                Write-Output "$(Convert-UTCtoLocal $($u.Date)), $operation, $resultcode, $($u.Title)"
                #TODO: make a nice object and a PSWUformat for this
            }
        } else {
            Write-Output "No Update History to show!"
        }
    }

}

function Get-UpdateList {
<#
.SYNOPSIS
Gets list of updates from Windows Update.
.DESCRIPTION
By default, output is columnized as shown in example 1.
The abbreviated column headers are:

 I O T H D R E MB
 | | | | | | |  |- Maximum download size, in megabytes
 | | | | | | |---- "E" if EULA accepted, "-" if not
 | | | | | |------ "R" if reboot required, "-" if not (frequently wrong!)
 | | | | |-------- "D" if the update has been downloaded, "-" if not
 | | | |---------- "H" if the update is hidden, "-" if not
 | | |------------ "S" if software, "D" if driver
 | |-------------- "O" if optional, "*" if not
 |---------------- "I" if installed, "-" if not
.PARAMETER Computername
The target computer. Defaults to the local PC. 
.PARAMETER  Criteria
The search criteria, see http://goo.gl/7nZSPs
Left at default, it will return all software updates that have not yet
been installed. Driver updates are ignored, but Hidden updates are shown
with the "H" flag set.
.PARAMETER SearchObject
This switch is used when an ISearchResult object (http://goo.gl/pvnUSM) must be 
returned. For most manual uses you can ignore this; the module will provide it 
when needed internally.
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

Shows that there are 5 updates available.
#>

    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$true, Position=0)] [string]$Computername = ".",
        [Parameter(ValueFromPipeline=$false, Position=1)] [string]$Criteria = "IsInstalled=0 and Type='Software'",
        [Parameter(Position=2)] [switch]$SearchObject
    )

    if (($Computername -ne ".") -and ($Computername -ne $env:COMPUTERNAME) -and ($Computername -ne "localhost") ) {
        #The following IF clause looks silly, but I could not find a cleaner way to send a switch param to remote PC
        #try this at some point: http://goo.gl/R0oi0F
        Compare-PSWU -Computername $Computername  
        Write-Verbose "Invoking Get-UpdateList on $Computername"
        if ($SearchObject) {
            $sb = {import-module PSWU; $output = Get-UpdateList -Computername . -Criteria $Using:Criteria -SearchObject; $output}
        } else {
            $sb = {import-module PSWU; $output = Get-UpdateList -Computername . -Criteria $Using:Criteria; $output}
        }
        Invoke-Command -ComputerName $Computername -ScriptBlock $sb
    } else {
        #running locally
        $Searcher = New-Object -ComObject Microsoft.Update.Searcher
        #$Searcher.Online = $false #try an offline search!
        $SecondsSpent = (Measure-Command {$ISearchResult = $Searcher.Search($Criteria)}).Seconds
        #$ISearchResult = $Searcher.Search($Criteria)
        if ($SearchObject) {$ISearchResult} else {$ISearchResult.Updates}
        $status = "$($ISearchResult.Updates.Count) update(s) found in $SecondsSpent seconds." 
        Write-Log -EventID 52 -Source Get-UpdateList -EntryType Information -Message $status
    }    
}

function Install-Update {
<#
.SYNOPSIS
Downloads and installs updates.
.PARAMETER Computername
The target computer. Defaults to the local PC. 
.PARAMETER SkipOptional
If this switch parameter is given, "Optional" updates will not be installed.
.PARAMETER Reboot
If this switch parameter is provided, the system will be rebooted - but *only*
if the update(s) installed left the system in a 'needs reboot' state.
.PARAMETER ISearchResult
An ISearchResult returned by the Get-UpdateList cmdlet.
If not provided, that cmdlet will be run to fetch one.
.PARAMETER OneByOne
Used for debugging. Allows only one update to be downloaded and installed.
.NOTES
Uses IUpdateDownloader http://goo.gl/hPK49j
and IUpdateInstaller http://goo.gl/jeDijU
WU error codes: http://goo.gl/cSWDY8
.EXAMPLE
Install-Update -Computername BensPC -Reboot
Installs outstanding (non-hidden) updates and reboots the computer if needed.
#>

    [CmdletBinding()]
    Param (
        [parameter(Position=0)][string]$Computername = ".",        
        [parameter(Position=1)][switch]$SkipOptional,
        [parameter(Position=2)][switch]$Reboot,
        [parameter(Position=3)]$ISearchResult,
        [parameter(Position=4)][switch]$OneByOne        
    )

    foreach ($key in $PSBoundParameters.Keys) {
        switch ($PSBoundParameters.$key) {
            $true {$boundparams += "-$key "}
            default {$boundparams += "-$key $($PSBoundParameters.$key) "}
        }
    }

    [bool]$rebootstatus = Test-RebootNeeded -Computername $Computername
    if ($rebootstatus -eq $true) {
        $status ="$Computername pending reboot status is: .$rebootstatus. - please reboot before applying further updates."
        Write-Log -EventID 20 -Source Install-Update -EntryType Error -Message $status
        break
    }
    
    if (($Computername -ne ".") -and ($Computername -ne $env:COMPUTERNAME) -and ($Computername -ne "localhost") ) {
        #this clause runs when a remote machine has been specified
        Compare-PSWU -Computername $Computername    
        if ($OneByOne) {
            $command = "&import-module pswu;Install-Update -OneByOne"
        } else {
            $command = "&import-module pswu;Install-Update"
        }
        $status = "Install-Update is sending an Install-Update task to $Computername"
        Write-Log -EventID 21 -Source Install-Update -EntryType Information -Message $status
        if ($Reboot) {
            New-PSTask -Computername $Computername -TaskName "PSWU Install-Update" -Command $command | Invoke-PSTask -Reboot -Follow
        } else {
            New-PSTask -Computername $Computername -TaskName "PSWU Install-Update" -Command $command | Invoke-PSTask -Follow
        }
        <# Hateful Note.             
           Creating/running a task on the remote PC and running is FAR FROM OPTIMAL.
           It's just the best thing I could come up with after multiple failed attempts.
           This is not a question of what user context the (remote) commands run in; I have tried as SYSTEM
           IUpdateDownloader (IUD) and IUpdateInstaller (IUI) refuse to be invoked remotely and they
           seem really good at knowing it, though I still don't know exactly *how* they know.           
           See https://goo.gl/Afi70J
           I tried:
           * http://serverfault.com/a/407379/3437 ... IUD knows it was called remotely
           * http://stackoverflow.com/a/14442352/2383 ... IUD knows
           * Pushing all of PSWU to remotePC then running it:
             * icm remotePC {import-module PSWU;install-update} ... IUD knows
             * icm remotePC {powershell.exe -command '&import-module pswu;install-update'} ... IUD knows
             * enter-pssession <sessionid> then run cmdlets local to remotePC ... IUD knows
             * Invoking powershell process via WMI as in http://goo.gl/Yy1iRP ... IUD knows
           * Kicking off WU itself as in https://goo.gl/Thm9k7 {wuauclt /detectnow ; wuauclt /updatenow}
             * There seems no clean way to rely on this, nor to find out when it completes.
        #>
    } else {
        #this clause runs when the cmdlet is invoked locally
        $infostring = "Install-Update ran locally (as $env:username)`r`n"
        $infostring += "Parameters given: $boundparams `r`n"
        If ((Test-AdminPrivs) -ne $true) {
            $status = "Admin privs required. Exiting. `r`n $infostring"
            Write-Log -EventID 22 -Source Install-Update -EntryType Error -Message $status
            break
        }

        if ($ISearchResult -eq $null) {
            $ISearchResult = Get-UpdateList -SearchObject            
        }
        if ($ISearchResult.pstypenames -notcontains 'System.__ComObject#{d40cff62-e08c-4498-941a-01e25f0fd33c}') {
            $status = "$ISearchResult is not an ISearchResult object (http://goo.gl/pvnUSM). Exiting. `r`n $infostring"
            Write-Log -EventID 24 -Source Install-Update -EntryType Error -Message $status
            break
        }
        if ($($ISearchResult.Updates.Count) -lt 1) {
            $status = "Found no available updates. Exiting. `r `n $infostring"
            Write-Log -EventID 25 -Source Install-Update -EntryType Information -Message $status
            break
        }
        
        # Iterate through available updates, sorting into two updatecollection objects: 
        # 1) the ones we want to install (Eligible) and 2) the ones we DO NOT want to install (Excluded)
        # Make a text list corresponing to each collection (used in event logs).

        $EligibleUpdates = New-Object -ComObject Microsoft.Update.UpdateColl
        $ExcludedUpdates = New-Object -ComObject Microsoft.Update.UpdateColl
        $EligibleUpdateList = ""
        $ExcludedUpdateList = ""
        
        foreach ($u in $ISearchResult.Updates) {
            [bool]$ApplyUpdate = $true
            [string]$Reason = "" #Reason for ineligibility
            if ($($u.IsHidden) -eq $true) {
                $ApplyUpdate = $false
                $Reason = "HIDDEN "
            }
            #"BrowseOnly" is seen in GUI as "Optional"; Don't apply if SkipOptional param is present    
            if (($SkipOptional -eq $true) -and ($($u.BrowseOnly) -eq $true)) {
                $ApplyUpdate = $false
                $Reason = "OPTIONAL"
            }
            
            if ($ApplyUpdate -eq $true) { 
                if (!$($u.EulaAccepted)) {$u.AcceptEula()}
                $EligibleUpdates.Add($u) |out-null 
                $EligibleUpdateList += "$($u.KBArticleIDs)`t$($u.Title)`r`n"
                if ($OneByOne) { 
                    #Used for debugging. One update at a time.
                    $UpdateList += "`r`nDebugging flag OneByOne was set.`r`n"
                    if ($EligibleUpdates.Count -gt 1) {break}
                }  
            } else {
                $ExcludedUpdates.Add($u) |out-null 
                $ExcludedUpdateList += "$($u.KBArticleIDs)`t$($u.Title)`t$Reason`r`n"
            }          
                
        }

        if ($EligibleUpdates.Count -lt 1) {
            $status = "No updates eligible for install, of $($ISearchResult.Updates.Count) found.`r`n"
            $status += "Ineligible updates: `r`n$ExcludedUpdateList"
            $status += "`r`nExiting. `r`n $infostring"
            Write-Log -EventID 22 -Source Install-Update -EntryType Information -Message $status
            break
        }
        
        $status = "Installing $($EligibleUpdates.Count) eligible updates; skipping $($ExcludedUpdates.Count) ineligible ones. `r`n"
        $status += "`r`nEligible updates to be downloaded and installed:`r`n$EligibleUpdateList`r`n"
        if ($($ExcludedUpdates.Count) -gt 0 ) {
            $status += "Inelegible updates that will not be installed:`r`n$ExcludedUpdateList`r`n"
        }
        $status += $infostring
        Write-Log -EventID 27 -Source Install-Update -EntryType Information -Message $status
        #IUpdateDownloader, https://goo.gl/hPK49j
        $Downloader = New-Object -ComObject Microsoft.Update.Downloader
        $Downloader.Updates = $EligibleUpdates
        $DownloadResult = $Downloader.Download()
        #Resultcode 2-success, 3-success with errors. 
        #Using -contains instead of -in for PS v2 compat
        if (2,3 -notcontains $DownloadResult.ResultCode) {
            $hexresult = "0x" + ('{0:x}' -f $($DownloadResult.ResultCode))
            $status = "Downloader error HResult $($DownloadResult.HResult), resultcode $($DownloadResult.ResultCode) `r`n"
            $status += "See https://support.microsoft.com/en-us/kb/938205 and error $hexresult `r`n"
            Write-Log -EventID 23 -Source Install-Update -EntryType Error -Message $status
        } else {
            if ($DownloadResult.ResultCode -eq 3) {$status = "Downloaded with errors; "}
            if ($DownloadResult.ResultCode -eq 2) {$status = "Downloaded successfully; "}
            $status += "beginning install of $($EligibleUpdates.Count) updates"
            Write-Log -EventID 24 -Source Install-Update -EntryType Information -Message $status
            $Installer = New-Object -ComObject Microsoft.Update.Installer
            $Installer.Updates = $EligibleUpdates
            $InstallResult = $Installer.Install()
            switch ($InstallResult.ResultCode) {
                2 {$status = "Installed updates successfully."}
                3 {$status = "Installed updates with errors."}
                default {
                    $hexresult = "0x" + '{0:x}' -f $($InstallResult.ResultCode)
                    $status = "Installer error $($InstallResult.HResult), resultcode $($InstallResult.ResultCode)"
                    $status += "See https://support.microsoft.com/en-us/kb/938205 and error $hexresult"
                    Write-Log -EventID 30 -Source Install-Update -EntryType Error -Message $status
                    return
                }
            }
            
            if ((Test-RebootNeeded) -eq $true) {
                if ($Reboot) {
                    Write-Log -EventID 25 -Source Install-Update -EntryType Information -Message "Updates installed; rebooting."
                    Restart-Computer -force
                } else {
                    Write-Log -EventID 25 -Source Install-Update -EntryType Warning -Message "Updates installed; please reboot soon."
                }
            } else {
                Write-Log -EventID 25 -Source Install-Update -EntryType Information -Message "Updates installed; reboot NOT needed."
            }
        }
        
    }
}

function Install-PSWU {
<#
.SYNOPSIS
Installs PSWU to remote computer.
.PARAMETER Computername
The target computer. Defaults to the local PC.
.PARAMETER Update
Updates the remote installation of PSWU to an exact copy of the
local installation.
.NOTES
Follow the rules at https://goo.gl/OjL8Nt
Note that Win7 and below do not have C:\Program Files\WindowsPowerShell\Modules
in $env:PSModulePath. I read the rules as saying it is OK to add that path.
.EXAMPLE
Install-PSWU CathyPC -Update
Installs or updates the PSWU module on the system named CathyPC.
#>

    [CmdletBinding()]
    Param (
        [parameter(Mandatory=$true, ValueFromPipeline=$true,Position=0)][string]$Computername,
        [parameter(Position=1)][switch]$Update        
    )

    Write-Verbose "Beginning Install-PSWU"
    #need a mechanism to remotely check whether module is usable
    #construct a UNC filepath to where the remote PSWU installation should be
    $RemoteSystemDrive = Invoke-Command -ComputerName $Computername {$env:SystemDrive}    
    $RemoteSysDriveShare = $RemoteSystemDrive -replace ":","$"
    $RemotePSWUDir = "\\" + $Computername + "\" + $RemoteSysDriveShare + "\Program Files\WindowsPowerShell\Modules\PSWU"
    [boolean]$PSWUdirExists = $true
    if (!(Test-Path $RemotePSWUDir)) {$Update = $true; $PSWUdirExists = $false}
    #if it is not there, install it
    if ($Update) {
        if ($PSWUdirExists) {
            Write-Verbose "Updating PSWU on $Computername"
        } else {
            Write-Verbose "$RemotePSWUDir DOES NOT exist on $Computername, installing PSWU there"
            New-Item -path $RemotePSWUDir -ItemType Directory | out-null
        }        
        #copy the files, unblock them
        $LocalPSWUPath = (Get-Module PSWU).ModuleBase
        Copy-Item $LocalPSWUPath\* $RemotePSWUDir -Force
        Unblock-File -Path $RemotePSWUDir\*
        #Win7 and below do not have the default PSModulePath '%systemdrive%\Program Files\WindowsPowerShell\Modules'  
        #detect this and add to SYSTEM profile if necessary
        $RemotePSModPath = Invoke-Command $Computername {[System.Environment]::GetEnvironmentVariable("PSModulePath", "Machine")}
        $PathToAdd = $RemoteSystemDrive + '\Program Files\WindowsPowerShell\Modules'        
        if (($RemotePSModPath -split ";") -NotContains $PathToAdd ) {
            $NewRemotePSModPath = $RemotePSModPath + ";" + $PathToAdd
            Invoke-Command $Computername {
                [System.Environment]::SetEnvironmentVariable("PSModulePath", $Using:NewRemotePSModPath, "Machine")
                import-module PSWU
                Get-ExecutionPolicy
            }            
        }
        Write-Verbose "PSWU installed/updated on $Computername"     
    }

}

function Compare-PSWU {
<#
.SYNOPSIS
Checks a remote computer to see if it has the same PSWU version installed locally. 
If PSWU is not present on the remote PC, it will be installed.
If PSWU on remote PC is a lesser version than local, the remote PSWU will be updated.
.PARAMETER Computername
The target computer. PSWU will be installed or updated on this computer.
.EXAMPLE
Compare-PSWU -Computername FrankenPC
TRUE
#>

    Param ([parameter(Mandatory=$true, ValueFromPipeline=$true,Position=0)][string]$Computername)

    try {
        $remotepswu = "SAME"
        $remotecommand = {import-module PSWU; (Get-Module PSWU).Version.ToString()}
        $remoteversion = Invoke-Command -ComputerName $Computername -ScriptBlock $remotecommand -HideComputerName -ErrorAction Stop
        $localversion = (Get-Module PSWU).Version.ToString()
        if ($localversion -gt $remoteversion) {$remotepswu = "OLDER"} 
        if ($localversion -lt $remoteversion) {$remotepswu = "NEWER"} 
    } catch {
        if ($($_.FullyQualifiedErrorId) -eq "NetworkPathNotFound,PSSessionStateBroken") {
            $remotepswu = "CANNOTCONNECT"
        } else {
            $remotepswu = "NOTPRESENT"
        }
    }

    switch ($remotepswu) {
        "SAME" {}
        "NOTPRESENT" {Install-PSWU -Computername $Computername}
        "OLDER" {Install-PSWU -Computername $Computername -update}
        "NEWER" {
            Write-Error "Exiting. $Computername has PSWU v$remoteversion which is newer than local version $localversion!"}        
        "CANNOTCONNECT" {Write-Error "Exiting. Cannot Connect to $Computername."}
        default {Write-Error "Exiting. WTF?"}
    }
}

function New-PSTask {
<#
.SYNOPSIS
Creates, runs, monitors, and finally deletes a Scheduled Task on a remote PC.
.DESCRIPTION
.PARAMETER Computername
The target computer. Defaults to the local PC.
.PARAMETER Command
The Powershell command(s) to be run by the remote scheduled task. 
.PARAMETER Reboot
If this switch parameter is given, the remote PC will be rebooted *if*
it is in a 'needs reboot' state.
.EXAMPLE
New-PSTask -Computername DanaPC -Command "&import-module pswu;Install-Update" -Reboot
The system named DanaPC will immediately run a scheduled task containing an 
Install-Update command. If this leaves DanaPC in a 'needs reboot' state, then it will
be rebooted.
.NOTES

#>
    [CmdletBinding()]
    Param (
        [parameter(Mandatory=$true, ValueFromPipeline=$true,Position=0)][string]$ComputerName,
        [parameter(Mandatory=$true, ValueFromPipeline=$true,Position=0)][string]$TaskName,
        [parameter(Mandatory=$true, ValueFromPipeline=$true,Position=1)][string]$Command,
        [parameter(ValueFromPipeline=$true,Position=2)][switch]$RunAtBoot
        
    )

    #Task Scheduler Scripting Objects https://goo.gl/iFYhlB 
    #Loosely emulating this example - https://goo.gl/9BHrQW
    #TaskService object, https://goo.gl/ewm1Th
    $Scheduler = New-Object -ComObject Schedule.Service
    #TODO: Check for existing task with this name. Especially if it is running!
    $Scheduler.Connect($ComputerName)
    if ($Scheduler.Connected) {
        $Task = $Scheduler.NewTask(0)
        #Task Definition Object https://goo.gl/UQbjMA
        $Task.Settings.MultipleInstances = 2 #Don't allow multiple instances of this task
        $Task.RegistrationInfo.Description = "Task created by PSWU script."
        #Principal object, https://goo.gl/u99qVL
        $Task.Principal.Runlevel = 1 #highest

        #Task Action definition https://goo.gl/3qA7Qy
        $Action = $Task.Actions.Create(0) #0 = Executable
        $Action.Path = "powershell.exe"
        $Action.Arguments = "-ExecutionPolicy Unrestricted -Command $Command"
        
        #Task Trigger (at boot) definition, example https://goo.gl/vl1CCL
        If ($RunAtBoot -eq $true) {$Task.Triggers.Create(8)}
        #and now we have an issue: the rest of this cmdlet tries to run the task immediately.

        #Taskfolder object, https://goo.gl/AWZM9j
        $TaskFolder = $Scheduler.GetFolder("\")
        $CreatedTask = $TaskFolder.RegisterTaskDefinition($TaskName, $Task, 6, "SYSTEM", $Null, 3)
        $status = "Task $TaskName was created on $ComputerName`r`n"
        $status += "Command: $Command"
        Write-Log -EventID 61 -Source New-PSTask -EntryType Information -Message $status

        #Output object for consumption by Invoke-Task
        $Properties = @{"ComputerName" = $ComputerName;
            "TaskName" = $TaskName;
            "TaskFolder" = $TaskFolder}
        $output = New-Object -TypeName PSObject -Property $Properties
        $output
    } else {
        $status = "Could not connect to Task Scheduler on computer $ComputerName `r`n"
        $status += "Params: `r`n $PSBoundParameters"
        Write-Log -EventID 62 -Source New-PSTask -EntryType Error -Message $status
    }
}

Function Invoke-PSTask {
<#
#>
    [CmdletBinding()]
    Param (
        [parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, Position=0)][string]$ComputerName,
        [parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, Position=1)][string]$TaskName,
        [parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, Position=2)]$TaskFolder,
        [parameter(ValueFromPipeline=$true, Position=3)][switch]$Reboot,
        [parameter(ValueFromPipeline=$true, Position=4)][switch]$Follow
    )

    Write-Verbose "Starting: $($MyInvocation.Line)"
    $Task = $TaskFolder.GetTask($TaskName)
    #Run task if verified in READY state
    if ($($Task.State) -ne 3) {
        Write-Warning "Invoke-Task is terminating; did not find task '$TaskName' in READY state."
        break
    } else {
        $TaskFolder.GetTask($TaskName).Run(0) |Out-Null
        Write-Verbose "Invoke-Task started task '$TaskName' in folder '$($TaskFolder.Name)' on $ComputerName."
        if ($Follow) {
            #Task should enter RUNNING state. Monitor for state change. 
            if ($($Task.State) -ne 4) {
                Write-Warning "Invoke-Task could not start task '$TaskName'."
            } else {
                Write-Verbose "'$TaskName' was started on $ComputerName. Waiting for completion:"
                $i = 0
                While ($($Task.State) -eq 4) {
                    Start-Sleep -Seconds 10
                    Write-Host -NoNewline "."
                    $i++
                }
                Write-Host
            }

            #Task states https://goo.gl/SugOUy
            switch ($($Task.State)) {
                0 {$state = "UNKNOWN"}
                1 {$state = "DISABLED"}
                2 {$state = "QUEUED"}
                3 {$state = "READY"}
                4 {$state = "RUNNING"}
            }
            Write-Verbose "PSWU task on $Computername is in $state state."

            #LastTaskResult states from https://goo.gl/rR128s
            #Apparently no MS docs on this; https://goo.gl/GRxUHz
            switch ($($Task.LastTaskResult)) {
                0 {$lastrunstate = "COMPLETED SUCCESSFULLY"}
                1 {$lastrunstate = "UNKNOWN/INCORRECT FUNCTION CALL"}
                2 {$lastrunstate = "FILE NOT FOUND"}
                10 {$lastrunstate = "INCORRECT ENVIRONMENT"}
            }
            Write-Verbose "PSWU task on $Computername last run state: $lastrunstate"

            #Delete the task, report pending-reboot status
            $TaskFolder.DeleteTask($TaskName,$Null)
            #Probly should move this logic to whichever cmdlet calls Invoke-PSTask
            if ((Test-RebootNeeded -Computername $Computername) -eq $true) {
                if ($Reboot) {
                    Write-Verbose "Task completed; rebooting $Computername."
                    Restart-Computer $Computername -force
                } else {
                    Write-Verbose "Task completed; please reboot $Computername."
                }
            } else {
                Write-Verbose "Task completed; $Computername does NOT need reboot."
            }
        }
    }
}

Function Convert-UTCtoLocal($UTCTime) {
<#
.SYNOPSIS
Translates a UTC date to one appropriate to the local timezone.
.PARAMETER UTCTime
The UTC date object which needs to be read as local time.
.NOTES
Thanks Tao Yang: http://goo.gl/R0w1Fk
.EXAMPLE
Convert-UTCtoLocal $dateobject
#>

    $strCurrentTimeZone = (Get-WmiObject win32_timezone).StandardName
    $TZ = [System.TimeZoneInfo]::FindSystemTimeZoneById($strCurrentTimeZone)
    $LocalTime = [System.TimeZoneInfo]::ConvertTimeFromUtc($UTCTime, $TZ)
    Return $LocalTime
}

Function Convert-ParamDictToString ($boundparams) {
<#
.SYNOPSIS
Converts a parameter dictionary ($PSBoundParameters) to a string in parameter format.
.PARAMETER boundparams
You'll pretty much always use $PSBoundParameters
.NOTES

.EXAMPLE
Convert-ParamHashToString $PSBoundParameters
#>
    if ($boundparams.GetType().Name -ne "PSBoundParametersDictionary") {
        throw "Convert-ParamToString requires a Hashtable."
    }
    $outstring = ""
    foreach ($key in $boundparams.Keys) {
        switch ($boundparams.$key) {
            $false {} #don't include switch params that evaluate false
            $true {$outstring += "-$key "} #do include switch params that are true, no need for the value
            default {$outstring += "-$key $($boundparams.$key) "} #include both param name and value for other param types
        }
    }
    $outstring

}
