
param (
    [Parameter(Mandatory= $False)]$basename,
    [Parameter(Mandatory)]$region,
    [Parameter(Mandatory= $False)]$vmSize = "Standard_DC2as_v5",
    [Parameter(Mandatory = $False)]$vnetname,
    [Parameter(Mandatory = $False)]$vmsubnetname,
    [Parameter(Mandatory = $False)][pscredential]$Creds,
    [Parameter(Mandatory = $False)]$KeyURL,
    [Parameter(Mandatory = $False)]$akvname,
    [Parameter(Mandatory = $False)]$keyName,
    [Parameter(Mandatory = $False)][ValidateSet("MHSM", "KeyVault")][string]$akvtype = "KeyVault",
    [Parameter(Mandatory = $False)]$resgrp,
    [Parameter(Mandatory = $False)]$desname,
    [Parameter(Mandatory = $False)]$vmname,
    [Parameter(Mandatory = $False)]$PublisherName='MicrosoftWindowsServer',
    [Parameter(Mandatory = $False)]$Offer='windowsserver',
    [Parameter(Mandatory = $False)]$Skus='2022-datacenter-smalldisk-g2',
    [Parameter(Mandatory = $False)]$Version="latest",
    [Parameter(Mandatory = $False)]$DataDiskSize
)  

# Validate that both parameters are either specified together or omitted together
if (($VNETName -and -not $VMSubnetName) -or ($VMSubnetName -and -not $VNETName)) {
    write-host "When specifying VNET or VMSubnet, both must be specified" -ForegroundColor Red
    return
    $command=read-host "Press CRTL-C to exit" 
    
}
#setting up the build
$basename = $basename + -join ((97..122) | Get-Random -Count 5 | % {[char]$_}) # basename + 5 random lower-case letters
If (!($vmname)){$vmname = $basename} # name of the VM, copied from $basename, or customise it here
If (!($resgrp)){$resgrp =  $basename} # name of the resource group where all resources will be created, copied from $basename
If (!($KeyURL -or $akvname)){$akvname = $basename + "akv"}    # name of the Key Vault
If (!($KeyURL-or $keyname)){$keyname = $basename + "-cmk-key"} #Name of the key in the Key Vault
If (!($vnetname)){$vnetname = $vmname + "vnet"} # name of the VNET
If (!($vmsubnetname)){$vmsubnetname = $basename + "vmsubnet"} # name of the VNET subnet
If (!($desname)){$desname = $basename + "-des"} # name of the disk encryption set



#when a Key URL is provided, we can extract the vault name from the key directly
If ($KeyURL){
    if ($KeyURL -match "vault.azure"){
        $akvtype = "KeyVault"
        $akvname = ($KeyURL -split ".vault.azure" -split "//")[1]
        $keyname=($KeyURL -split "/keys/" -split "/")[3]
        $desname=($keyname + "-des")
    }elseif($KeyURL -match ".managedhsm.azure.net"){
        $akvtype = "MHSM"
        $akvname = ($KeyURL -split ".managedhsm.azure.net" -split "//")[1]
        $keyname=($KeyURL -split "/keys/" -split "/")[3]
        $desname=($keyname + "-des")
    }else{
        Write-host "Wrong KeyURL"
        #exit
    }
}


#Loading PSM1 module
If (Get-Module -Name KeyVault){
    Remove-Module -Name KeyVault
}
Import-Module -Name .\KeyVault.psm1

$vmSecurityType = "ConfidentialVM";
$diskEncryptionType = "ConfidentialVmEncryptedWithCustomerKey";
$secureEncryptGuestState = "DiskWithVMGuestState";

#Get username of logged-in Azure user to grant access
$tmp = Get-AzContext
$ownername = $tmp.Account.Id


        #Cosmetic stuff
        write-host ""
        write-host ""
        write-host "                               _____        __                                " -ForegroundColor Green
        write-host "     /\                       |_   _|      / _|                               " -ForegroundColor Yellow
        write-host "    /  \    _____   _ _ __ ___  | |  _ __ | |_ _ __ __ _   ___ ___  _ __ ___  " -ForegroundColor Red
        write-host "   / /\ \  |_  / | | | '__/ _ \ | | | '_ \|  _| '__/ _' | / __/ _ \| '_ ' _ \ " -ForegroundColor Cyan
        write-host "  / ____ \  / /| |_| | | |  __/_| |_| | | | | | | | (_| || (_| (_) | | | | | |" -ForegroundColor DarkCyan
        write-host " /_/    \_\/___|\__,_|_|  \___|_____|_| |_|_| |_|  \__,_(_)___\___/|_| |_| |_|" -ForegroundColor Magenta
        write-host "     "
        write-host " This script deploys a CVM with all required components" -ForegroundColor "Green"
        write-host " You have selected" -ForegroundColor "Green"
        write-host "  - VM name:" -NoNewline -ForegroundColor "Blue"
        write-host $vmname -ForegroundColor "Cyan"
        write-host "  - VM Size:" -NoNewline -ForegroundColor "Blue"
        write-host $vmsize -ForegroundColor "Cyan"
        write-host "  - Vnet Name:" -NoNewline -ForegroundColor "Blue"
        write-host $vnetName -ForegroundColor "Cyan"
        write-host "  - Subnet Name:" -NoNewline -ForegroundColor "Blue"
        write-host $vmsubnetname -ForegroundColor "Cyan"
        write-host "  - Resource Group:" -NoNewline -ForegroundColor "Blue"
        write-host $resgrp -ForegroundColor "Cyan"
        write-host "  - KeyVault Name:" -NoNewline -ForegroundColor "Blue"
        write-host $akvname -ForegroundColor "Cyan"
        write-host "  - KeyVault Type:" -NoNewline -ForegroundColor "Blue"
        write-host $akvtype -ForegroundColor "Cyan"
        write-host "  - Key Name:" -NoNewline -ForegroundColor "Blue"
        write-host $keyname -ForegroundColor "Cyan"
        if ($KeyURL) {
            write-host "  - KeyURL:" -NoNewline -ForegroundColor "Blue"
            write-host $KeyURL -ForegroundColor "Cyan"
        }
        
        
        write-host "  - Credentials:" -ForegroundColor "Blue" -NoNewline
        If ($Creds) {
            #validate that creds are correctly specified
            Write-host "   - supplied"  -ForegroundColor Blue 
            Write-host "   - Username:"  -ForegroundColor Blue -NoNewline
            write-host $creds.username -ForegroundColor Cyan
            write-host "   - Password:" -NoNewline -ForegroundColor "Blue"
            Write-Host " <provided>" -ForegroundColor Cyan
            If ($creds.Password.GetType().name -ne "SecureString"){
                Write-Host " Creds are not correct" -ForegroundColor Red
                Read-Host -Prompt "Press CRTL-X to exit"
            }
        }else{
            Write-Host "   - not specified, generating"  -ForegroundColor Yellow
            $creds=GenerateCreds
        }
        
        write-host "  - Publisher:" -NoNewline -ForegroundColor "Blue"
        write-host $PublisherName -ForegroundColor "Cyan"
        write-host "  - Offer:" -NoNewline -ForegroundColor "Blue"
        write-host $Offer -ForegroundColor "Cyan"
        write-host "  - Source:" -NoNewline -ForegroundColor "Blue"
        write-host $Skus -ForegroundColor "Cyan"
        write-host "  - Version:" -NoNewline -ForegroundColor "Blue"
        write-host $Version -ForegroundColor "Cyan"
    
        write-host ""
        write-host ""
#Actual Script Logica
#validate if an existing VM exists
    If (get-azvm -Name $vmname){
        Write-Host "VM already exists" -foregroundcolor red
        write-host ""
        write-host ""
    }else{
        write-host "CVM Operator AppID check: " -ForegroundColor Blue -NoNewline
        If (ValidateCVMOperator){
            write-host "ok" -ForegroundColor Green
        }
        write-host "ResourceGroup check: "-ForegroundColor Blue -NoNewline
        $check=ValidateResourceGroup -resgrp $resgrp -region $region

        if(!($KeyURL)){
            $KeyVault=ValidateKeyVault -Type $akvtype -akvname $akvname -region $region -resgrp $resgrp -ownername $ownername
        }

        write-host "KeyVault access " -NoNewline -ForegroundColor Blue
        $key=ValidateKey -akvname $akvname -Type $akvtype -ownername $ownername -keyname $keyname -resgrp $resgrp;
        if ($key.id){
            write-host $key.id -ForegroundColor Cyan
        }else {
            Read-Host -Prompt "Press CRTL-X to exit"
        }
        $keyID=$key.id

        $diskencset=CreateDiskEncryptionSet -keyId $keyId -KeyName $keyName -region $region -resgrp $resgrp -desname $desname -akvname $akvname -EncryptionType $diskEncryptionType -Type $akvtype;
        $SubnetID=ValidateVNET -vnetname $vnetname -subnetName $vmsubnetname -region $region -resgrp $resgrp;
        write-host "subnetID:" -ForegroundColor Blue -NoNewline
        write-host $subnetID -ForegroundColor Cyan
        $nicId=CreateNIC -subnetId $SubnetID -resgrp $resgrp -region $region -vmname $vmname;


        $diskencset=get-azdiskencryptionset -Name $desname -ResourceGroupName $resgrp
        ##OVERVIEW##
 

        Write-Host "Creating VM Config"
        Write-Host "- VMName, VMSize, " -NoNewline
        $VirtualMachine = New-AzVMConfig -VMName $VMName -VMSize $vmSize;
        Write-Host "Operating System, Credentials, Updates" -NoNewline
        $VirtualMachine = Set-AzVMOperatingSystem -VM $VirtualMachine -Windows -ComputerName $vmname -Credential $creds -ProvisionVMAgent -EnableAutoUpdate;
        Write-Host ", Source Image" -NoNewline
        $VirtualMachine = Set-AzVMSourceImage -VM $VirtualMachine -PublisherName $PublisherName -Offer $Offer -Skus $Skus -Version $Version;
        Write-Host ", NIC" -NoNewline
        $VirtualMachine = Add-AzVMNetworkInterface -VM $VirtualMachine -Id $nicId;
        Write-Host ", OS Disk" -NoNewline
        $VirtualMachine = Set-AzVMOSDisk -VM $VirtualMachine -StorageAccountType "StandardSSD_LRS" -CreateOption "FromImage" -SecurityEncryptionType $secureEncryptGuestState -SecureVMDiskEncryptionSet $diskencset.id;
        Write-Host ", Security Profile" -NoNewline
        If ($DataDiskSize){
            Write-Host ", Data Drive" -NoNewline
            $VirtualMachine = Add-AzVMDataDisk -VM $VirtualMachine -Name "datadisk" -DiskSizeInGB $DataDiskSize -CreateOption Empty -Caching ReadWrite -StorageAccountType StandardSSD_LRS -lun 0;
        }
        $VirtualMachine = Set-AzVmSecurityProfile -VM $VirtualMachine -SecurityType $vmSecurityType;
        Write-Host ", Secure Boot" -NoNewline
        $VirtualMachine = Set-AzVmUefi -VM $VirtualMachine -EnableVtpm $true -EnableSecureBoot $true;
        Write-Host ", Diagnostic Settings"
        #$VirtualMachine = Set-AzVMBootDiagnostic -VM $VirtualMachine -disable #disable boot diagnostics, you can re-enable if required

        Write-Host "Building VM" -ForegroundColor Green
        $NewVM=New-AzVM -ResourceGroupName $resgrp -Location $region -Vm $VirtualMachine
        #$vm = Get-AzVm -ResourceGroupName $resgrp -Name $vmname;
        IF ($DataDiskSize) {
            Write-host "Enabling BitLocker on Data drive" -ForegroundColor Green
            $path=((get-location).path + "\")
            If (Test-Path ($path + "EnableBitLocker.ps1")) {
                Invoke-AzVMRunCommand -ResourceGroupName $resgrp -VMName $vmname -CommandId 'RunPowerShellScript' -ScriptPath ($path + "EnableBitLocker.ps1")
            }else{
                Write-host "BitLocker script not found" -ForegroundColor Red
            }
        }
    }
    write-host " This script deployed a CVM with all required components" -ForegroundColor "Green"
