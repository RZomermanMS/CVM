#MyScript
Write-host "Enabling BitLocker on DATA DRIVES"

#Initialize raw disks
[array]$me=get-disk | where {$_.PartitionStyle -eq "RAW"} 
ForEach ($disk in $me) {
    Initialize-Disk -Number $disk.Number -PartitionStyle GPT -PassThru | New-Partition -AssignDriveLetter -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel "DATA" -Confirm:$false
}
#Get All unprotected Disks
[array]$VolumesToBeProtected=Get-BitLockerVolume | where {$_.ProtectionStatus -eq "Off"}
If ($VolumesToBeProtected.Count -eq 0) {
    Write-Host "No Volumes to be protected"
    Exit
}else{
    $ProtectorArray = @()
    foreach ($Volume in $VolumesToBeProtected) {
        Enable-BitLocker -MountPoint $Volume.MountPoint -EncryptionMethod Aes256 -RecoveryPasswordProtector
        Enable-BitLockerAutoUnlock -MountPoint $Volume.MountPoint
        $Recovery=(Get-BitLockerVolume -MountPoint $Volume.MountPoint).KeyProtector.recoverypassword
        Write-Host "Recovery Key for Drive $($Volume.DriveLetter) is $Recovery"
        $ProtectorArray += $Recovery
    }
}


write-host ""
write-host "**********************"
Write-host "SAVE THE RECOVERY KEYS"
write-host "**********************"
ForEach ($Protector in $ProtectorArray) {
    write-host $Protector
}
write-host "**********************"
Write-host "SAVE THE RECOVERY KEYS"
write-host "**********************"
write-host ""

