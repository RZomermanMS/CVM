This script will deploy a CVM in super secret configuration. Currently it only supports Managed HSM backed keys (KeyVault to be done) 
usage: 


Mandatory parameters: 
-region uaenorth
-resgrp <resourcegroupname>

Many parameters are optional.. 
-vmSize  (default)=Standard_DC2as_v5   make sure to always select a DCa or ECa series
-creds    (generated if not specified)
-vmname (generated if not specified)
-basename (used if you do not specify all parameters are base for new objects)
-akvname (Managed HSM name) (generated if not specified)
-akvtype (KeyVault/MHSM) (autodetect is keyURL is used, else default MHSM)
-vnetname (created if not specified based on $vmname+vnet)
-subnetname (created if not specified based on $basename+vmsubnet)
.\keyvault.ps1 -region uaenorth -vmSize Standard_DC2as_v5 -Creds $creds -resgrp MANAGEDHSM -vmname CVM032 -akvname mhsmrcz01 -akvtype MHSM -KeyURL "https://mhsmrcz01.managedhsm.azure.net:443/keys/MyKey2/9cd941aae5e24eaa02d8cd796634e3a2"
