#requires -version 5.0
#requires -RunAsAdministrator
<#
.SYNOPSIS
   Migrates an existing NSG to a new NSG
.DESCRIPTION
   The purpose of this Azure resource manipulation script is to migrate an existing NSG with rules and an association with a NIC or subnet to a new NSG which will have an association with a new NIC or subnet. This is accomplished by
   (1) Exporting the rules of the existing NSG, (2) Creating the new NSG, (3) Applying the rules that were exported from the existing NSG to the new NSG. (4) Next, we will associate the new NSG to a specified subnet before (5) Disassociating
   the original NSG from the NIC to which it was previously assigned. A customized log with time-stamps to indicate summary of activities performed by this script will be recorded in the file assigned to the $Log varaible, while a 
   more detailed logging of script execution, appropriate for troubleshooting and auditing will be available from the file referenced in the $Transcript variable.
.EXAMPLE
   New-AzureRmNsgMigration -SubscriptionName <> -rg <> -Region <> -SourceNsg <> -SourceNic <> -TargetSubnet <> -TargetVNET <> -DisassociateSource
.EXAMPLE
   New-AzureRmNsgMigration -SubscriptionName <> -rg <> -Region <> -SourceNsg <> -SourceNic " -TargetSubnet <> -TargetVNET <>
.PARAMETERS
   -SubscriptionName - The name of the subscription in which the NSG rules will be migrated
   -rg - The name of the resource group in which the source Nsg resource that will be migrated exists
   -Region - The name of the region associated with the resource group
   -SourceNsg - The source NSG resource that will be migrated
   -SourceNic - The source NIC that the sourc NSG is associated to
   -TargetSubnet - The target subnet to which the new NSG resource will be associated, with firewall rules applied, that were exported from the source NSG
   -TargetVNET - The vnet which contains the target subnet that will be associated with the target NSG
   -DisassociateSource - This is an optional switch parameter to specify whether the source NSG will be dissasociated from it's originally associated target
.OUTPUTS

.NOTES
   REQUIREMENTS: WriteToLogs module (https://www.powershellgallery.com/packages/WriteToLogs)
   LIMITATIONS: TBD
   AUTHOR(S)  : Preston K. Parsard
   EDITOR(S)  : Preston K. Parsard
   KEYWORDS	  : Azure, NSG, Firewall, Rules
   
   REFERENCES : 
   https://msdn.microsoft.com/en-us/powershell/reference/5.1/microsoft.powershell.core/about/about_comment_based_help
   https://blogs.msdn.microsoft.com/igorpag/2016/05/14/azure-network-security-groups-nsg-best-practices-and-lessons-learned/
   http://www.gi-architects.co.uk/2015/11/addsetremove-nsg-rules-in-arm-mode-azure-powershell/
   https://www.petri.com/create-azure-network-security-group-using-arm-powershell
   https://msdn.microsoft.com/en-us/library/aa965353(VS.85).aspx

   The MIT License (MIT)
   Copyright (c) 2017 Preston K. Parsard

   Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), 
   to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software. 

   LEGAL DISCLAIMER:
   This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment.  
   THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, 
   INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  
   We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code form of the Sample Code, provided that You agree: 
   (i) to not use Our name, logo, or trademarks to market Your software product in which the Sample Code is embedded; 
   (ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded; and 
   (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys’ fees, that arise or result from the use or distribution of the Sample Code.
   This posting is provided "AS IS" with no warranties, and confers no rights.

.COMPONENT
   Azure IaaS
.ROLE
   Azure IaaS Administrators/Engineers
.FUNCTIONALITY
   Migrates Nsg rules from an existing NSG to a new one.
#>

<# 
TASK ITEMS
#>

<# 
***************************************************************************************************************************************************************************
REVISION/CHANGE RECORD	
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------
DATE         VERSION    NAME            CHANGE
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------
26 JUL 2017  1.0.0.0 Preston K. Parsard Initial release.
#>

Param
(
    # Name of Azure subscription
    [Parameter(Mandatory=$true, 
               Position=0)]
    [ValidateNotNullOrEmpty()]
    [string]$SubscriptionName,

    # Resource Group containing the source (and target) NSGs
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$rg,

    # Azure Region associated with the specified resource group
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$Region,

    # Source NSG containing rules that will be migrated to the new NSG
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$SourceNsg,

    # Source NIC name that the source NSG is associated with
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$SourceNic,

    # Target subnet that will be associated with the target NSG
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$TargetSubnet,

    # Target VNET which contains the target subnet which will be associated with the target NSG
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$TargetVNET,

    # Include this parameter if the source NSG will be disassociated from it's target (NIC or Subnet)
    [switch]$DisassociateSource

) #end param

# Resets profiles in case you have multiple Azure Subscriptions and connects to your Azure Account [Uncomment if you haven't already authenticated to your Azure subscription]
Clear-AzureProfile -Force
Login-AzureRmAccount

# Construct custom path for log files 
$LogDir = "New-AzureRmNsgMigration"
$LogPath = $env:HOMEPATH + "\" + $LogDir
If (!(Test-Path $LogPath))
{
 New-Item -Path $LogPath -ItemType Directory
} #End If

# Create log file with a "u" formatted time-date stamp
$StartTime = (((get-date -format u).Substring(0,16)).Replace(" ", "-")).Replace(":","")
$24hrTime = $StartTime.Substring(11,4)

$LogFile = "New-AzureRmNsgMigration-LOG" + "-" + $StartTime + ".log"
$TranscriptFile = "New-AzureRmNsgMigration-TRANSCRIPT" + "-" + $StartTime + ".log"
$Log = Join-Path -Path $LogPath -ChildPath $LogFile
$Transcript = Join-Path $LogPath -ChildPath $TranscriptFile
# Create Log file
New-Item -Path $Log -ItemType File -Verbose
# Create Transcript file
New-Item -Path $Transcript -ItemType File -Verbose

Start-Transcript -Path $Transcript -IncludeInvocationHeader -Append -Verbose

# To avoid multiple versions installed on the same system, first uninstall any previously installed and loaded versions if they exist
Uninstall-Module -Name WriteToLogs -AllVersions -ErrorAction SilentlyContinue -Verbose

# If the WriteToLogs module isn't already loaded, install and import it for use later in the script for logging operations
If (!(Get-Module -Name WriteToLogs))
{
 # https://www.powershellgallery.com/packages/WriteToLogs
 Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
 Install-PackageProvider -Name Nuget -ForceBootstrap -Force 
 Install-Module -Name WriteToLogs -Repository PSGallery -Force -Verbose
 Import-Module -Name WriteToLogs -Verbose
} #end If

#region INITIALIZE VALUES	

$BeginTimer = Get-Date -Verbose

# Selects subscription
Select-AzureRmSubscription -SubscriptionName $SubscriptionName

# Create and populate prompts object with property-value pairs
# PROMPTS (PromptsObj)
$PromptsObj = [PSCustomObject]@{
 pVerifySummary = "Is this information correct? [YES/NO]"
 pAskToOpenLogs = "Would you like to open the deployment log now ? [YES/NO]"
} #end $PromptsObj

# Create and populate responses object with property-value pairs
# RESPONSES (ResponsesObj): Initialize all response variables with null value
$ResponsesObj = [PSCustomObject]@{
 pProceed = $null
 pOpenLogsNow = $null
} #end $ResponsesObj

$DelimDouble = ("=" * 100 )
$Header = "AZURE RM NSG MIGRATION SCRIPT: " + $StartTime

# Create the NSG name using 'NSG-' as a prefix
$TargetNsgName = "NSG-$TargetSubnet"
$nsgResourceType = "Microsoft.Network/networkSecurityGroups"

# Populate Summary Display Object
# Add properties and values
# Make all values upper-case
 $SummObj = [PSCustomObject]@{
 SUBSCRIPTION = $SubscriptionName.ToUpper()
 RESOURCEGROUP = $rg.ToUpper()
 REGION = $Region.ToUpper()
 SOURCENSG = $SourceNsg.ToUpper()
 SOURCENIC = $SourceNic.ToUpper()
 TARGETSUBNET = $TargetSubnet.ToUpper()
 TARGEVNET = $TargetVNET.ToUpper()
 TARGETNSG = $TargetNsgName.ToUpper()
 LOGPATH = $Log
 } #end $SummObj
 
#endregion INITIALIZE VALUES

#region FUNCTIONS	

#endregion FUNCTIONS

#region MAIN	

# Clear screen
# Clear-Host 

# Display header
Write-ToConsoleAndLog -Output $DelimDouble -Log $Log
Write-ToConsoleAndLog -Output $Header -Log $Log
Write-ToConsoleAndLog -Output $DelimDouble -Log $Log

# Display Summary
Write-ToConsoleAndLog -Output $SummObj -Log $Log
Write-ToConsoleAndLog -Output $DelimDouble -Log $Log

# Verify parameter values
Do {
$ResponsesObj.pProceed = read-host $PromptsObj.pVerifySummary
$ResponsesObj.pProceed = $ResponsesObj.pProceed.ToUpper()
}
Until ($ResponsesObj.pProceed -eq "Y" -OR $ResponsesObj.pProceed -eq "YES" -OR $ResponsesObj.pProceed -eq "N" -OR $ResponsesObj.pProceed -eq "NO")

# Record prompt and response in log
Write-ToLogOnly -Output $PromptsObj.pVerifySummary -Log $Log
Write-ToLogOnly -Output $ResponsesObj.pProceed -Log $Log

# Exit if user does not want to continue

if ($ResponsesObj.pProceed -eq "N" -OR $ResponsesObj.pProceed -eq "NO")
{
  Write-ToConsoleAndLog -Output "Deployment terminated by user..." -Log $Log
  PAUSE
  EXIT
 } #end if ne Y
else 
{
    # Proceed with NSG migration
    Write-ToConsoleAndLog -Output "Migrating source NSG to new target..." -Log $Log
    Write-WithTime -Output "Retrieving source NSG resource..." -Log $Log -Verbose 
    $SourceNsgResource = Get-AzureRmNetworkSecurityGroup -Name $SourceNsg -ResourceGroupName $rg -Verbose

    Write-WithTime -Output "Retrieving source NSG security rules..." -Log $Log -Verbose
    $SourceNsgRules = $SourceNsgResource.SecurityRules

    Write-WithTime -Output "Creating new target NSG resource..." -Log $Log -Verbose
    $TargetNsgResource = New-AzureRmNetworkSecurityGroup -Name $TargetNsgName -ResourceGroupName $rg -Location $Region -Verbose
    Write-Debug "`$TaretNsgResource $TargetNsgResource"

    Write-WithTime -Output "Applying source NSG rules to target NSG resource..." -Log $Log -Verbose
    # Add rules for new target NSG resource
    ForEach ($SourceNsgRule in $SourceNsgRules)
    {
        # An error is produced if the description is null or empty, so here we are hard-coding a place-holder text of 'null' to avoid this terminating error.
        Switch ($SourceNsgRule.Description)
        {
            $null { $SourceNsgRule.Description = "null" }
        }

        Add-AzureRmNetworkSecurityRuleConfig -Name $SourceNsgRule.Name `
        -NetworkSecurityGroup $TargetNsgResource `
        -Access $SourceNsgRule.Access `
        -Description $SourceNsgRule.Description `
        -DestinationAddressPrefix $SourceNsgRule.DestinationAddressPrefix `
        -DestinationPortRange $SourceNsgRule.DestinationPortRange `
        -Direction $SourceNsgRule.Direction `
        -Priority $SourceNsgRule.Priority `
        -Protocol $SourceNsgRule.Protocol `
        -SourceAddressPrefix $SourceNsgRule.SourceAddressPrefix `
        -SourcePortRange $SourceNsgRule.SourcePortRange |
        Set-AzureRmNetworkSecurityGroup -Verbose
        
    } #end foreach

    # Associate target NSG resource to target subnet

    Write-WithTime -Output "Retrieving VNET resource info..." -Log $Log -Verbose
    $vnet = Get-AzureRmVirtualNetwork -Name $TargetVNET -ResourceGroupName $rg -Verbose

    Write-WithTime -Output "Retrieving target subnet resource info..." -Log $Log -Verbose
    $TargetSubnetResource = $vnet.Subnets.GetEnumerator() | Where-Object { $_.Name -match "$TargetSubnet" }

    Write-WithTime -Output "Associating target NSG to required target subnet..." -Log $Log -Verbose
    Set-AzureRmVirtualNetworkSubnetConfig -VirtualNetwork $vnet -Name $TargetSubnetResource.Name -AddressPrefix $TargetSubnetResource.AddressPrefix -NetworkSecurityGroup $TargetNsgResource | Set-AzureRmVirtualNetwork -Verbose

    # Disassociate source NSG from source NIC if desired
    If ($DisassociateSource)
    {
        Write-WithTime -Output "Checking if source NSG is associated with NIC..." -Log $Log -Verbose
        If ($SourceNsgResource.NetworkInterfaces.Count -gt 0)
        { 
            Write-WithTime -Output "Source NSG is associated with NIC. Disassociating NSG from NIC..." -Log $Log -Verbose
            $SourceNicResource = Get-AzureRmNetworkInterface -Name $SourceNic -ResourceGroupName $rg -Verbose
            $SourceNicResource.NetworkSecurityGroupText
            $SourceNicResource.NetworkSecurityGroup = $null
            Set-AzureRmNetworkInterface -NetworkInterface $SourceNicResource -Verbose 
        } #end if
    } #end if
} #end else

#endregion MAIN

#region FOOTER		

# Calculate elapsed time
Write-WithTime -Output "Calculating script execution time..." -Log $Log
Write-WithTime -Output "Getting current date/time..." -Log $Log
$StopTimer = Get-Date
$EndTime = (((Get-Date -format u).Substring(0,16)).Replace(" ", "-")).Replace(":","")
Write-WithTime -Output "Calculating elapsed time..." -Log $Log
$ExecutionTime = New-TimeSpan -Start $BeginTimer -End $StopTimer

$Footer = "SCRIPT COMPLETED AT: "

Write-ToConsoleAndLog -Output $DelimDouble -Log $Log
Write-ToConsoleAndLog -Output "$Footer $EndTime" -Log $Log
Write-ToConsoleAndLog -Output "TOTAL SCRIPT EXECUTION TIME: $ExecutionTime" -Log $Log
Write-ToConsoleAndLog -Output $DelimDouble -Log $Log

# Prompt to open logs
Do 
{
 $ResponsesObj.pOpenLogsNow = read-host $PromptsObj.pAskToOpenLogs
 $ResponsesObj.pOpenLogsNow = $ResponsesObj.pOpenLogsNow.ToUpper()
}
Until ($ResponsesObj.pOpenLogsNow -eq "Y" -OR $ResponsesObj.pOpenLogsNow -eq "YES" -OR $ResponsesObj.pOpenLogsNow -eq "N" -OR $ResponsesObj.pOpenLogsNow -eq "NO")

# Exit if user does not want to continue
if ($ResponsesObj.pOpenLogsNow -eq "Y" -OR $ResponsesObj.pOpenLogsNow -eq "YES") 
{
 Start-Process notepad.exe $Log
 Start-Process notepad.exe $Transcript
} #end if

# End of script
Write-WithTime -Output "END OF SCRIPT!" -Log $Log

# Close transcript file
Stop-Transcript -Verbose

#endregion FOOTER

Pause