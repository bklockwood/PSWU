#requires -version 2.0

[string]$ScriptName = $($MyInvocation.MyCommand.Name)
[string]$ScriptPath = split-path $SCRIPT:MyInvocation.MyCommand.Path 
[string]$ScriptFullPath = $SCRIPT:MyInvocation.MyCommand.Path
try {    
    import-module -name $ScriptPath   
} catch {
    $Logtext = "Could not import the PSWU module; exiting."
    Out-file -FilePath $Logfile -Append -NoClobber -InputObject $Logtext -Encoding ascii
    break
}   

Install-AllUpdates -DontRunThisCmdletManually "PermissionGranted" `
    -ScriptName $ScriptName `
    -Scriptpath $ScriptPath `
    -ScriptFullName $ScriptFullPath `
    -Verbose
