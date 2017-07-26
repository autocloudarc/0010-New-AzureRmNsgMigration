# 0010-New-AzureRmNsgMigration
   The purpose of this Azure resource manipulation script is to migrate an existing NSG with rules and an association with a NIC or subnet to a new NSG which will have an association with a new NIC or subnet. This is accomplished by
   (1) Exporting the rules of the existing NSG, (2) Creating the new NSG, (3) Applying the rules that were exported from the existing NSG to the new NSG. (4) Next, we will associate the new NSG to a specified subnet before (5) Disassociating
   the original NSG from the NIC to which it was previously assigned. A customized log with time-stamps to indicate summary of activities performed by this script will be recorded in the file assigned to the $Log varaible, while a 
   more detailed logging of script execution, appropriate for troubleshooting and auditing will be available from the file referenced in the $Transcript variable.
