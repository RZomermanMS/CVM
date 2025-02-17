Function ValidateKeyVault($Type,$akvname,$region,$resgrp,$ownername){
# Function to create a KeyVault or Managed HSM and returns the keyvault object
# Create Key Vault
If ($Type -eq "KeyVault"){
    #need to check if exists
    $Hostname=($akvname + ".vault.azure.net")
    write-host "Validating KeyVault: "  -ForegroundColor Blue -NoNewline
    write-host $Hostname -ForegroundColor Cyan
        $result = Resolve-DnsName $Hostname -ErrorAction SilentlyContinue
        if ($result) {
            Write-Host "KeyVault Name already exists" -foregroundcolor Green -NoNewline
            $keyvault=Get-AzKeyVault -Name $akvname 
            if (!($keyvault)){
                Write-Host "Cannot connect" -foregroundcolor Red
                $confirmation = Read-Host "Press CTRL-C to cancel this script"
            }elseif ($keyvault.SKU -ne "Premium"){
                Write-Host "KeyVault is not a Premium SKU" -foregroundcolor Red
                $confirmation = Read-Host "Press CTRL-C to cancel this script"
            }elseif($keyvault.EnabledForDiskEncryption -ne $true){
                Write-Host "KeyVault is not enabled for disk encryption" -foregroundcolor Red
                $confirmation = Read-Host "Press CTRL-C to cancel this script"
            }elseif($keyvault.EnablePurgeProtection -ne $true){
                Write-Host "KeyVault does not have purge protection enabled - enabling" -foregroundcolor Yellow
                Update-AzKeyVault -EnablePurgeProtection -Name $akvname -ResourceGroupName $resgrp
            }else{
                Write-Host " and available for use" -foregroundcolor Green
                return $keyvault
            }
        } else {
            Write-Host " KeyVault does not yet exist, " -NoNewline
            write-Host "creating" -ForegroundColor Yellow
            $keyvault=New-AzKeyVault -Name $akvname -Location $region -ResourceGroupName $resgrp -Sku Premium -EnabledForDiskEncryption -DisableRbacAuthorization -SoftDeleteRetentionInDays 10 -EnablePurgeProtection;
            return $keyvault
        }
}elseif($Type -eq "MHSM"){
    # Try to resolve the hostname
    $Hostname=($akvname + ".managedhsm.azure.net")
    write-host "Validating Managed HSM: "  -ForegroundColor Blue -NoNewline
    write-host $Hostname -ForegroundColor Cyan
    $result = Resolve-DnsName $Hostname -ErrorAction SilentlyContinue
        if ($result) {
            Write-Host "Managed HSM name already exists" -foregroundcolor Green -NoNewline
            $keyvault=Get-AzKeyVaultManagedHsm -Name $akvname 
            $status=($keyvault | select ProvisioningState).ProvisioningState
            if (!($status)){
                Write-Host "Cannot connect" -foregroundcolor Red
                $confirmation = Read-Host "Press CTRL-C to cancel this script"
            }
            elseif ($status -eq "Provisioning") {
                Write-host " still being provisioned, please wait for it to complete" -foregroundcolor orange
                $confirmation = Read-Host "Press CTRL-C to cancel this script"
            } elseif ($status -eq "Succeeded") {
                Write-Host " and provisioned" -foregroundcolor Green -NoNewline
                ActivateMHSM -akvname $akvname
                return $keyvault
            }else{
                Write-Host "Cannot connect" -foregroundcolor Red
                $confirmation = Read-Host "Press CTRL-C to cancel this script"
            }
            
        } else {
            Write-Host "Creating Managed HSM"
            Write-Host "!!WARNING: The Managed HSM will be created with 7 days soft delete and purge protection enabled - this will incur costs, even after deletion!!"
            # Prompt user for confirmation
            $confirmation = Read-Host "Press Y to continue"
            if ($confirmation -ne 'Y') {
                Write-Host "Operation cancelled."
                #exit
            }
            #ADDED FOR COST CONTROL
            $tags = @{"CostControl"="Ignore"}
            $keyvault=New-AzKeyVaultManagedHsm -ResourceGroupName $resgrp -Name $akvname -Sku StandardB1 -Location $region -Administrator $ownername -SoftDeleteRetentionInDays 7 -EnablePurgeProtection -tags $tags
             Write-Output "Creating the managed HSM Instance.. please be patient"
            Start-Sleep -Seconds 30
            $status=(Get-AzKeyVaultManagedHsm -Name $akvname | select ProvisioningState).ProvisioningState
            While ($status -eq "Provisioning") {
                Write-Host "."  -NoNewline -ForegroundColor Yellow
                Start-Sleep -Seconds 10
                $status=(Get-AzKeyVaultManagedHsm -Name $akvname | select ProvisioningState).ProvisioningState
            }
            ActivateMHSM -akvname $akvname
            return $keyvault
        }
    }
}

Function ActivateMHSM($akvname){
    $MyHSM=(Get-AzKeyVaultManagedHsm -Name $akvname)
    if ($MyHSM.SecurityDomain.ActivationStatus -eq "NotActivated") { 
        Write-host " - Activating Managed HSM" -ForegroundColor Yellow
        GenerateCerts
        #activate the managed HSM with the generated certs
        $path=((get-location).path + "\")
        Export-AzKeyVaultSecurityDomain -Name $akvname -Certificates ($path + "cert1.cer"), ($path + "cert2.cer"), ($path + "cert3.cer") -OutputPath "MHSMsd.ps.json" -Quorum 2
        start-sleep -Seconds 30
        if ($MyHSM.SecurityDomain.ActivationStatus -eq "Activated"){
            Write-host "Managed HSM activated" -ForegroundColor Green
        }
    } elseif($MyHSM.SecurityDomain.ActivationStatus -eq "Active") {
        Write-host " and activated" -ForegroundColor Green
    }else{
        Write-host "Managed HSM status unkown" -ForegroundColor Red
        Read-Host -Prompt "Press CTRL-C to exit"
    }
}

Function CreateDiskEncryptionSet($keyName,$KeyID,$region,$resgrp,$desname, $akvname, $keyvault, $Type, $encryptionType){
    #if a disk encryption set already exists, we will check it
    If ($diskEncryptionSet=Get-AzDiskEncryptionSet -ResourceGroupName $resgrp -Name $desname -ErrorAction SilentlyContinue){
        write-host "Disk Encryption Set already exists - validating key" -ForegroundColor Yellow -NoNewline
        $SourceKey=$diskEncryptionSet.ActiveKey.KeyUrl
        $SourceVault=$diskEncryptionSet.ActiveKey.SourceVault
        $SourceKeyName=($SourceKey -split "/keys/" -split "/")[3]
        $SourceVaultName= ($SourceVault.id -split "/")[$_.count -1]
        If (!($SourceVaultName -eq $akvname -and $SourceKeyName -eq $keyName)){
            write-host " - key is different!" -ForegroundColor Red
            Read-Host -Prompt "Press CTRL-C to exit"
        }else{
            write-host " - OK" -ForegroundColor Green
        }
        $diskEncryptionSetID=$diskEncryptionSet.id
        return $diskEncryptionSetID
    }else{
        write-host "Validating new Disk Encryption Set " -NoNewline -ForegroundColor Blue
        write-host "$desname" -ForegroundColor Cyan
      
        # Create Disk Encryption Set
        #creating new User Assigned Identity to access the key
        write-host "- validating user assigned identity: "  -NoNewline
        write-host $keyName -NoNewline -ForegroundColor Cyan
        If (!($identity=Get-AzUserAssignedIdentity -Name $keyName -ResourceGroupName $resgrp -ErrorAction SilentlyContinue)){
            write-host " - creating" -ForegroundColor Yellow
            $identity=New-AzUserAssignedIdentity -ResourceGroupName $resgrp -Name $keyName -Location $region
            start-sleep -Seconds 5
        }
        #assigning permissions to the key:
        write-host "- validating permissions on key for user: "  -NoNewline
        write-host $identity.name -ForegroundColor Cyan
        if ($Type -eq "KeyVault"){
            Set-AzKeyVaultAccessPolicy -VaultName $akvname -ResourceGroupName $resgrp -ObjectId $identity.PrincipalId -PermissionsToKeys wrapKey,unwrapKey,get -BypassObjectIdValidation;
        }else{#ManagedHSM)
            write-host "Setting permissions on key for Managed HSM"
            ValidateHSMRoles2 -akvname $akvname -identity $identity.ClientId -role "Managed HSM Crypto Service Encryption User" -scope ("/keys/" + $keyName)
            ValidateHSMRoles2 -akvname $akvname -identity $identity.ClientId -role "Managed HSM Crypto User" -scope ("/keys/" + $keyName)
            ValidateHSMRoles2 -akvname $akvname -identity $identity.ClientId -role "Managed HSM Crypto Service Release User" -scope ("/keys/" + $keyName)
            #NEED TO MAKE ADJUSTMENTS IN CASE THIS DOES NOT EXIST YET
            $org=Get-AzADServicePrincipal -DisplayName "Confidential VM Orchestrator"
            write-host "- validating permissions on key for: " -NoNewline -ForegroundColor Blue
            write-host $org.DisplayName -ForegroundColor Cyan
            ValidateHSMRoles2 -akvname $akvname -identity $org.AppId -role "Managed HSM Crypto Service Release User" -scope ("/keys/" + $keyName)
        }

        If ($Type -eq "KeyVault"){
            $keyvault = Get-AzKeyVault -Name $akvname
        }else{
            write-host "- validating Managed HSM access " -NoNewline
            $keyvault = Get-AzKeyVaultManagedHsm -Name $akvname
            write-host $keyvault.resourceid -ForegroundColor Green
        }
        If (!($keyvault)){
            Write-Output "KeyVault not reachable"
            Read-Host -Prompt "Press Enter to exit"
        }

        $userAssignedIdentities = @{$identity.id = @{}};
        write-host "- creating new disk encryption set config"
        $diskEncryptionSetConfig=New-AzDiskEncryptionSetConfig -Location $region -IdentityType UserAssigned -SourceVaultId $keyvault.resourceid -KeyUrl $keyId -UserAssignedIdentity $userAssignedIdentities -EncryptionType $encryptionType
        write-host "- creating new disk encryption set " -NoNewline -ForegroundColor Yellow
        write-host $desname -ForegroundColor Cyan
        $diskEncryptionSet = New-AzDiskEncryptionSet -ResourceGroupName $resgrp -Name $desname -InputObject $diskEncryptionSetConfig
        Write-Host "Disk Encryption Set created" -ForegroundColor Green
        $diskEncryptionSetID=$diskEncryptionSet.id
        return $diskEncryptionSetID
    }
}


Function ValidateHSMRoles2($akvname,$identity, $role, $scope){
    Write-host "- validating $scope access for:"  -NoNewline
    write-host $identity -NoNewline -ForegroundColor Cyan
    $ExistingRoles=Get-AzKeyVaultRoleAssignment -HsmName $akvname -scope $scope
    if ($identity -match "@"){
        $UPN=$true
    }
    If ($ExistingRoles | where-Object {$_.DisplayName.Contains($identity)} |Where-Object {$_.RoleDefinitionName.Contains($role)}){
        Write-Host " - role is assigned" -ForegroundColor Green
    }else{
        Write-Host " - assigning" -ForegroundColor Yellow
            If ($UPN){
                New-AzKeyVaultRoleAssignment -HsmName $akvname -RoleName $role -SignInName $identity -scope $scope
            }else{
                New-AzKeyVaultRoleAssignment -HsmName $akvname -RoleName $role -ApplicationID $identity -scope $scope
            }
    }
}

Function ValidateHSMRoles($akvname,$ownername){
    $ExistingRoles=Get-AzKeyVaultRoleAssignment -HsmName $akvname -SignInName $ownername -scope /keys
    If ($ExistingRoles | Where-Object {$_.RoleDefinitionName.Contains("Managed HSM Crypto User")}){
        Write-Output "Role is assigned"
    }else{
        New-AzKeyVaultRoleAssignment -HsmName $akvname -RoleName "Managed HSM Crypto User" -SignInName $ownername -scope /keys
        }
}
Function ValidateKeyVaultAccess($akvname,$ownername, $resgrp){
    $keyvault=Get-AzKeyVault -Name $akvname
    $RBAC=$keyvault.EnableRbacAuthorization
    if ($RBAC -eq $false){
        write-host " validating access to vault for " -NoNewline
        write-host "$ownername" -NoNewline -ForegroundColor Cyan
        $UserID=(Get-AzADUser -UserPrincipalName $ownername).Id
        $AccessPolicies=$keyvault.AccessPolicies
        [array]$UserPolicies=$AccessPolicies | where {$_.ObjectID -match $UserID}
        If ($UserPolicies.PermissionsToKeys -contains "all"){
            write-host " - has access to all keys" -ForegroundColor Green
        }else{
            write-host " - does not have access to trying to grant" -ForegroundColor Red
            $confirmation=read-host "Press CTLR-C to cancel"
        }
        [array]$CVMOrg=$AccessPolicies | where {$_.displayName -match "Confidential VM Orchestrator"}
        write-host " validating access to vault for " -NoNewline
        write-host " Confidential VM Orchestrator" -NoNewline -ForegroundColor Cyan
        If ($CVMOrg.PermissionsToKeys -contains "get" -and $CVMOrg.PermissionsToKeys -contains "release"){
            write-host " - has " -NoNewline
            write-host "get-release" -ForegroundColor Green -NoNewline
            write-host " access to all keys"
        }else{
            write-host " - granting access" -ForegroundColor Yellow
            $cvmAgent = Get-AzADServicePrincipal -ApplicationId 'bf7b6499-ff71-4aa2-97a4-f372087be7f0';
            $newPolicy=Set-AzKeyVaultAccessPolicy -VaultName $akvname -ResourceGroupName $resgrp -ObjectId $cvmAgent.id -PermissionsToKeys get,release;
        }
    }else{
        #need to implement RBAC mode   
        write-host "RBAC mode is ON"
    }
}
Function ValidateKey($akvname,$Type,$ownername, $keyname, $resgrp){
    #Function validates if a key exists, if not, it will create one (if we have permissions) function returns the key object    
    if($Type -eq "KeyVault"){
        Write-Host "KeyVault " -ForegroundColor Green
        #Standard KeyVault entries to be made
        ValidateKeyVaultAccess -akvname $akvname -ownername $ownername -resgrp $resgrp
        $key=Get-AzKeyVaultKey -VaultName $akvname -Name $keyname -ErrorAction SilentlyContinue
    }elseif($Type -eq "MHSM"){
        #validating access to the keys in managed HSM
        Write-Host "ManagedHSM " -ForegroundColor Green
        ValidateHSMRoles2 -akvname $akvname -identity $ownername -role "Managed HSM Crypto User" -scope /keys
        $key=Get-AzKeyVaultKey -HsmName $akvname -Name $keyname -ErrorAction SilentlyContinue
    }

    #validating if a key already exists
    if ($key) {
        Write-Host "Key exists - " -ForegroundColor Green -NoNewline
        Write-host "validating" -noNewLine
        if ($key.ReleasePolicy.PolicyContent){
            Write-Host " - key has a release policy for: " -ForegroundColor Green -NoNewline
            $keyPolicy=($key.ReleasePolicy.PolicyContent -split 'authority":"' -split '/"}')[1]
            write-host $keyPolicy -ForegroundColor Cyan
        }else{
            Write-Host " - key does not have a release policy and cannot be used " -ForegroundColor red
            Read-Host -Prompt "Press CRTL-C to exit"
        }
        return $key
    }else{
        #generate new key
        write-host "- creating new key in "  -ForegroundColor Yellow -NoNewline
        $path=((get-location).path + "\")
        if($Type -eq "KeyVault"){
            write-host " $akvname :"  -ForegroundColor Green -NoNewline
            $key=Add-AzKeyVaultKey -VaultName $akvname -Name $KeyName -Size 3072 -KeyOps wrapKey,unwrapKey -KeyType RSA -Destination HSM -Exportable -UseDefaultCVMPolicy;
        }elseif($Type -eq "KeyVault"){
            write-host " $akvname :"  -ForegroundColor Green -NoNewline
            $key=Add-AzKeyVaultKey -HsmName $akvname -Name $keyname -KeyType RSA -Size 3072 -Exportable -ReleasePolicyPath ($path + "release.json")
        }
        return $key
    }
}

Function ValidateVNET($vnetname, $subnetName, $region, $resgrp){
    #Validates if a network exists, else it will create one and return the subnet ID
    Write-host "Validating VNET" -NoNewline
    $vnet = Get-AzVirtualNetwork -Name ($vnetname)
    If (!($Vnet)){
        Write-host " - creating vnet ($vnetname) with 10.0.0.0/24 and subnet ($subnetName) 10.0.0.0/26" -ForegroundColor Yellow
        $subnet = New-AzVirtualNetworkSubnetConfig -Name ($subnetName) -AddressPrefix "10.0.0.0/26";
        $vnet = New-AzVirtualNetwork -Force -Name ($vnetname) -ResourceGroupName $resgrp -Location $region -AddressPrefix "10.0.0.0/24" -Subnet $subnet;
        #$vnet = Get-AzVirtualNetwork -Name ($vnetname) -ResourceGroupName $resgrp;
        $subnetId = $vnet.Subnets[0].Id;    
        return $subnetId  
    }else{
        write-host (" - " + $vnet.name) -ForegroundColor Green -NoNewline
        If ($Vnet.location -ne $region){
            Write-host "VNET is in a different region" -ForegroundColor red
            #exit
        }
        If ($subnet = Get-AzVirtualNetworkSubnetConfig -Name $subnetName -VirtualNetwork $vnet){
            Write-Host (" - " + $subnet.Name) -ForegroundColor Green   
            $subnetId = $subnet.Id
        }else{
            Write-Host "Subnet does not exist" -ForegroundColor Red
            #exit

        }
    return $subnetId   
    }
}

Function CreateNIC($subnetId, $resgrp, $region, $vmname){
    #Create the NIC and link it to the subnet
    Write-host "Validating NIC " -NoNewline
    $nicname = $vmname + "-nic1"
    $nic=Get-AzNetworkInterface -name $nicname
    If ($nic){
        Write-Host ("- already exists - " + $nic.Name) -ForegroundColor Green
        $nicId = $nic.Id
        return $nicId
    }else{
        Write-Host "- creating" -ForegroundColor Yellow
        $nic = New-AzNetworkInterface -Name $nicname -ResourceGroupName $resgrp -Location $region -SubnetId $subnetId
        $nicId = $nic.Id
        return $nicId
    }
}
Function GenerateCerts(){
    $certNames = @("cert1", "cert2", "cert3")
    $path=((get-location).path + "\")
    $certStoreLocation = "Cert:\CurrentUser\My"
    
    foreach ($name in $certNames) {
        # Generate self-signed certificate
        $cert = New-SelfSignedCertificate -Subject "CN=$name" -KeyAlgorithm RSA -KeyLength 2048 -CertStoreLocation $certStoreLocation
    
        # Export the certificate (Public Key) as Base64 PEM
        #$certPath = ($path + "$name-public.pem")
        Export-Certificate -Cert $cert -FilePath ($path + "$name.cer")
        #$certBase64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes(($path + "$name.cer"))) -replace ".{64}", "$&`n"
        #Set-Content -Path $certPath -Value "-----BEGIN CERTIFICATE-----`n$certBase64`n-----END CERTIFICATE-----" -NoNewline
    }
    
    Write-Host "Certificates and keys have been successfully generated!"
    Write-Host "Note that the full certificates (including private keys required for restore) are stored in the user Certificate Store."
    
    }

Function GenerateCreds(){
    #Function to generate credentials for the VM
    $vmusername = "azureuser" # you can adjust this if you want
    $vmadminpassword = -join ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%".ToCharArray() | Get-Random -Count 40) # build a random password - note you can't get it back afterwards
    #create a credential object
    write-host "----------------------------------------------------------------------------------------------------------------"
    write-host "IMPORTANT - no creds where specified - building random creds for the VM"
    write-host "VM admin username is " $vmusername
    write-host "passsword for the VM is " $vmadminpassword " - save this now as you CANNOT retrieve it later"
    write-host "----------------------------------------------------------------------------------------------------------------"
    $securePassword = ConvertTo-SecureString -String $vmadminpassword -AsPlainText -Force # this could probably be done better inline rather than via a variable
    $cred = New-Object System.Management.Automation.PSCredential ($vmusername, $securePassword);
    return $cred
}
Function ValidateResourceGroup($resgrp, $region){
    #Function to validate if a resource group exists, if not, it will create one
    $rg=Get-AzResourceGroup -Name $resgrp -ErrorAction SilentlyContinue
    If ($rg){
        Write-Host "ok" -ForegroundColor Green
    }else{
        Write-Host "creating" -ForegroundColor Yellow
        $rg=New-AzResourceGroup -Name $resgrp -Location $region | out-null
    }
    return $rg

}
Function ValidateCVMOperator(){
    #need to validate if the Confidential VM Orchestrator exists
    $org=Get-AzADServicePrincipal -DisplayName "Confidential VM Orchestrator"
    if (!($org)){
        write-host " - The " -ForegroundColor Yellow -NoNewline
        write-host "Confidential VM Orchestrator" -ForegroundColor Cyan -NoNewline
        write-host " does not exist in your tenant - you will need to sign-in to the Graph to create " -ForegroundColor Yellow -NoNewline
        Connect-Graph Application.ReadWrite.All
        New-MgServicePrincipal -AppId bf7b6499-ff71-4aa2-97a4-f372087be7f0 -DisplayName "Confidential VM Orchestrator" 
        start-sleep -Seconds 5
        $org=Get-AzADServicePrincipal -DisplayName "Confidential VM Orchestrator"
        if (!($org)){
            write-host " SOMETIHNG WENT WRONG " -ForegroundColor RED  -NoNewline
            write-host " please run: " -ForegroundColor RED  -NoNewline
            write-host "Connect-Graph -Tenant 'your tenant ID' Application.ReadWrite.All" -ForegroundColor Yellow
            write-host "New-MgServicePrincipal -AppId bf7b6499-ff71-4aa2-97a4-f372087be7f0 -DisplayName 'Confidential VM Orchestrator'" -ForegroundColor Yellow
            Read-Host -Prompt "Press CTRL-C to exit"
        }
        return $true
    }elseif($org.AppId -eq 'bf7b6499-ff71-4aa2-97a4-f372087be7f0'){
        return $true
    }else{
        write-host "Something is wrong with the Confidential VM Orchestrator app" -ForegroundColor Red
        Read-Host -Prompt "Press CTRL-C to exit"
    }
}
