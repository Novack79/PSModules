# Get number of enabled users, enabled computers and member groups of AD groups.
function Get-ADGroupEnabledCount
{
    [CmdletBinding()]
    Param (
    [parameter(Mandatory=$true,ValueFromPipeline=$true)]
    [object] $Group
    )

    begin {
        $listReturn = New-Object Collections.Generic.List[Object]
    }

    process {

         $strContainer = Get-ADObjectContainer -ADObject $Group

         $objGroup = [pscustomobject] @{
                Container = $strContainer
                Name = $Group.Name
                Category = $Group.GroupCategory
                Scope = $Group.GroupScope
                Computers = 0
                Users = 0
                Groups = 0
                Foreign = 0
         }

        $Members = (Get-ADGroup -Identity $Group.DistinguishedName -Properties member).member
        Write-Verbose $Group.DistinguishedName
        foreach($strMember in $Members)
        {
            # Do not attempt to resolve foreign security principals
            if($strMember -like '*CN=ForeignSecurityPrincipals*')
            {
                $objGroup.Foreign++

            } else {
                $Member = Get-ADObject -Identity $strMember -Properties objectClass
                switch($Member.objectClass)
                {
                    "computer" {
                        $Member = Get-ADComputer -Identity $strMember -Properties Enabled
                        if($Member.Enabled) {$objGroup.Computers++}
                        break;
                    }
                    "user" {
                        $Member = Get-ADUser -Identity $strMember -Properties Enabled
                        if($Member.Enabled) {$objGroup.Users++}
                        break;
                    }
                    "group" {
                        $objGroup.Groups++
                        break;
                    }
                }
            }
        }

        $listReturn.Add($objGroup)
    }

    end {
        return $listReturn
    }

}

# Return all group objects in Active Directory Domain, possibly filtered by a root OU
function Get-AllADGroups
{
    [CmdletBinding()]
    Param (
    [parameter(Mandatory=$true,HelpMessage='FQDN of Active Directory domain to be queried for groups')]
    [string] $Domain,
    [parameter(Mandatory=$false)]
    [string] $Root = "root"
    )

    if($Root -eq "root")
    {
        $Groups = Get-ADGroup -Filter * -Server $Domain
    } else {
        $Groups = Get-ADGroup -Filter * -Server $Domain -SearchBase $Root
    }

    return $Groups

}

function Get-NestedGroups
{
    [CmdletBinding()]
    Param (
    [parameter(Mandatory=$true,ValueFromPipeline=$true)]
    [object] $Group
    )

    begin {
        $listReturn = New-Object Collections.Generic.List[Object]
    }

    process {
        $memberGroups = Get-ADGroupMember -Identity $Group | where {$_.objectClass -eq 'group'}

        foreach($member in $memberGroups)
        {
            $objGroup = [pscustomobject] @{
                Group = $Group.Name
                Member = $member.Name
           }

           $listReturn.Add($objGroup)
       }


    }

    end {
        return $listReturn
    }

}

# Count AD objects by organizational unit in the array of AD objects.
#
# NOTE! The function ONLY counts the objects passed onto it. It does NOT query AD for members of OUs. The calling function must make any
# necessary filtering of the objects to be counted and only pass the objects it wants counted.
#
# Returns a list of PSObjects with the following properties:
# - Parent - Canonical name of the containing OU
# - ObjClass - Class of objects counted in this OU
# - Count - Number of objects (by object class) counted in this OU
function Get-ADObjectCountByOU
{
    [CmdletBinding()]
    Param (
    [parameter(Mandatory=$true,HelpMessage='objects to count',ValueFromPipeline=$true)]
    [object] $objADObject
    )

    begin {
        $listReturn = New-Object Collections.Generic.List[Object]
    }

    process {
       
        # Obtain the object to be counted. The passed on object may be missing the "CanonicalName" property that we need so we have to get the
        # object again here.
        $object = Get-ADObject -Identity $objADObject.DistinguishedName -Properties CanonicalName,ObjectClass

        # Parse the container OU canonical name since the object CN also contains the object name
        $strParent = Get-ADContainerFromCN -CanonicalName $object.CanonicalName

        # Shorthand variable for the object class name
        $strObjClass = $objADObject.ObjectClass.ToString()

        # Initialize loop variables
        $bFound = $false
        
        # Check the list of objects to be returned if an object for the same OU and object class already exists. 
        # If it does, increment the count.
        foreach($objOUCount in $listReturn)
        {
            if($objOUCount.Parent -eq $strParent -and $objOUCount.ObjClass -eq $strObjClass)
            {
                # If we find a match, increment the Count property and set $bFound boolean to true so we know we found a match
                $objOUCount.Count++
                $bFound = $true

                # We can only have one match so when/if it is found, break the loop to save processing time
                break
            }
        }

        # If no match was found in the loop above, create a new object for this OU and object class and set the count to 1.
        if($bFound -eq $false)
        {
            $objOU = New-Object PSObject -Property @{
                Parent = $strParent
                ObjClass = $strObjClass
                Count = 1
            }

        # Add the object to the return list (update the existing object if one already exists).
        $listReturn.Add($objOU)

        }

    }

    end {
       return $listReturn
    }

}

function Get-ADContainerFromCN 
{
    [CmdletBinding()]
    Param (
    [parameter(Mandatory=$true,ValueFromPipeline=$true)]
    [string] $CanonicalName
    )

    $intParentIndex = $CanonicalName.LastIndexOf('/')
    $strParent = $CanonicalName.Substring(0,$intParentIndex)
    return $strParent

}

function Get-ADObjectContainer
{
    [CmdletBinding()]
    Param (
    [parameter(Mandatory=$true,ValueFromPipeline=$true)]
    [object] $ADObject
    )

    $objCN = Get-ADObject -Identity $ADObject.DistinguishedName -Properties CanonicalName
    return (Get-ADContainerFromCN -CanonicalName $objCN.CanonicalName)
}

function Get-ADObjectDate
{
    [CmdletBinding()]
    Param (
    [parameter(Mandatory=$true,ValueFromPipeline=$true)]
    [object] $ADObject,
    [parameter(Mandatory=$true)]
    [ValidateSet("LastLogin","WhenCreated","WhenChanged")]
    [string] $DateType,
    [parameter(Mandatory=$false)]
    [string] $DateFormat
    )

    $ADObject = Get-ADObject -Identity $ADObject -Properties ObjectClass,whenCreated,whenChanged
    $dateReturn = $null

    switch($DateType)
    {
       "LastLogin" {
            if($ADObject.ObjectClass -eq "computer")
            {
                $LogonTimeStamp = (Get-ADComputer -Identity $ADObject -Properties LastLogonTimestamp).LastLogonTimestamp
            } elseif ($ADObject.ObjectClass -eq "user") {
                $LogonTimeStamp = (Get-ADUser -Identity $ADObject -Properties LastLogonTimestamp).LastLogonTimestamp
            } else {
                Write-Error "LastLoginDate is not supported by objectClass $($ADObject.ObjectClass)"
                break;
            }

            $dateReturn = [datetime]::FromFileTime($LogonTimeStamp)
            break;
       }

       "WhenCreated" {
            $dateReturn = [datetime]$ADObject.whenCreated
            break;
       }

       "WhenChanged" {
            $dateReturn = [datetime]$ADObject.whenChanged
            break;
       }

    }

    
    if($DateFormat -ne $null -and $dateReturn -ne $null)
    {
         $dateReturn = $dateReturn.ToString($DateFormat)
    }

    return $dateReturn
}

function Get-GPLinks
{
    [CmdletBinding()]
    Param (
    [parameter(Mandatory=$true,ValueFromPipeline=$true)]
    [string] $DistinguishedName
    )

    $arrReturn = Get-GPInheritance $DistinguishedName | Select -ExpandProperty GPOLinks

    return $arrReturn

}

function GEt-AllGPOsReport
{
    [CmdletBinding()]
    Param (
    [parameter(Mandatory=$true)]
    [string] $ExportPath,
    [parameter(Mandatory=$true,ValueFromPipeline=$true)]
    [object] $Domain,
    [parameter(Mandatory=$true)]
    [ValidateSet("Html","Xml")]
    [string] $ReportType,
    [parameter(Mandatory=$false)]
    [switch] $ShowDisabled = $false
    )

    # Process the domain root GPOs
    $strFolderPath = $ExportPath + '\' + $Domain.DNSRoot
    $arrGPOs = Get-GPLinks -DistinguishedName $Domain.DistinguishedName

    if($arrGPOs -ne $null)
    {
         If((Test-Path $strFolderPath) -ne $true)
         {
            Write-Host "Creating Path $strFolderPath" -ForegroundColor Cyan
            $null = (New-Item -ItemType Directory -Path $strFolderPath)
         }
         foreach($objGPO in $arrGPOs)
         {
            $strDisplay = $objGPO.DisplayName
            if($objGPO.Enforced -eq $true) { $strDisplay = 'ENF-' + $strDisplay}
            if($objGPO.Enabled -ne $true) { $strDisplay = 'DIS-' + $strDisplay}
            $strExport = "$strFolderPath\$($strDisplay).html"
            $strExport = $strExport.Replace('/',' ')
            Write-Host "Exporting Report for $($objGPO.DisplayName) to $strExport" -ForegroundColor Green
            Get-GPOReport -Guid $objGPO.GPOId -ReportType $ReportType -Path $strExport
         }
    }

    # Process all organizational units in the domain
    $ADOUs = Get-ADOrganizationalUnit -SearchBase $Domain.DistinguishedName -Filter * -Properties canonicalName

    foreach($objOU in $ADOUs)
    {
        $strFolderPath = $ExportPath + '\' + $objOU.canonicalName.replace('/','\')
        $arrGPOs = Get-GPLinks -DistinguishedName $objOU.DistinguishedName

        if($arrGPOs -ne $null)
        {
            If((Test-Path $strFolderPath) -ne $true)
            {
                Write-Host "Creating Path $strFolderPath" -ForegroundColor Cyan
                $null = (New-Item -ItemType Directory -Path $strFolderPath)
            }

            foreach($objGPO in $arrGPOs)
            {
                if($objGPO.Enabled -eq $true -or $ShowDisabled -eq $true)
                {
                    $strDisplay = $objGPO.DisplayName
                    if($objGPO.Enforced -eq $true) { $strDisplay = 'ENF-' + $strDisplay}
                    if($objGPO.Enabled -ne $true) { $strDisplay = 'DIS-' + $strDisplay}
                    $strExport = "$strFolderPath\$($strDisplay).html"
                    $strExport = $strExport.Replace('/',' ')
                    Write-Host "Exporting Report for $($objGPO.DisplayName) to $strExport" -ForegroundColor Green
                    Get-GPOReport -Guid $objGPO.GPOId -ReportType $ReportType -Path $strExport
                }
            }
        
        }
    }
}

function Copy-ADUser
{
    [CmdletBinding()]
    Param (
    [parameter(Mandatory=$true,ValueFromPipeline=$true)]
    [object] $SourceUser,
    [parameter(Mandatory=$true)]
    [string] $FirstName,
    [parameter(Mandatory=$true)]
    [string] $LastName,
    [parameter(Mandatory=$true)]
    [string] $UserPrincipalName,
    [parameter(Mandatory=$true)]
    [string] $LoginName
    )

    $objNewUser = Get-ADUser -Identity $SourceUser -Properties *

}

function New-ADOUPath
{
    [CmdletBinding()]
    Param (
    [parameter(Mandatory=$true,ValueFromPipeline=$true)]
    [object] $OrganizationalUnit
    )

    # Map Active Directory to PS Drive
    if (-not (Get-PSDrive -Name 'AD' -ErrorAction Silent)) {
        Throw [System.Management.Automation.DriveNotFoundException] "$($Error[0]) You're likely using an older version of Windows ($([System.Environment]::OSVersion.Version)) where the 'AD:' PSDrive isn't supported."
    }


}

function Get-ADAllOUParents
{
    [CmdletBinding()]
    Param (
    [parameter(Mandatory=$true,ValueFromPipeline=$true)]
    [object] $OrganizationalUnit
    )


}

function Get-DomainGPOReport
{

    [CmdletBinding()]
    Param (
    [parameter(Mandatory=$true,ValueFromPipeline=$true)]
    [string] $strDomain,
    [parameter(Mandatory=$true)]
    [string] $strExportFolderPath
    )

    $ADOUs = Get-ADOrganizationalUnit -SearchBase $strDomain -Filter * -Properties canonicalName

    $objDom = Get-ADDomain -Identity $strDomain
    $strFolderPath = $strExportFolderPath + '\' + $objDom.DNSRoot
    $arrGPOs = Get-GPLinks -DistinguishedName $strDomain

    if($arrGPOs -ne $null)
    {
         If((Test-Path $strFolderPath) -ne $true)
         {
            Write-Host "Creating Path $strFolderPath" -ForegroundColor Cyan
            $null = (New-Item -ItemType Directory -Path $strFolderPath)
         }
         foreach($objGPO in $arrGPOs)
         {
            $strDisplay = $objGPO.DisplayName
            if($objGPO.Enforced -eq $true) { $strDisplay = 'ENF-' + $strDisplay}
            if($objGPO.Enabled -ne $true) { $strDisplay = 'DIS-' + $strDisplay}
            $strExport = "$strFolderPath\$($strDisplay).html"
            $strExport = $strExport.Replace('/',' ')
            Write-Host "Exporting Report for $($objGPO.DisplayName) to $strExport" -ForegroundColor Green
            Get-GPOReport -Guid $objGPO.GPOId -ReportType 'Html' -Path $strExport
         }
    }

    foreach($objOU in $ADOUs)
    {
        $strFolderPath = $strExportFolderPath + '\' + $objOU.canonicalName.replace('/','\')
        $arrGPOs = Get-GPLinks -DistinguishedName $objOU.DistinguishedName

        if($arrGPOs -ne $null)
        {
            If((Test-Path $strFolderPath) -ne $true)
            {
                Write-Host "Creating Path $strFolderPath" -ForegroundColor Cyan
                $null = (New-Item -ItemType Directory -Path $strFolderPath)
            }

            foreach($objGPO in $arrGPOs)
            {
                $strDisplay = $objGPO.DisplayName
                if($objGPO.Enforced -eq $true) { $strDisplay = 'ENF-' + $strDisplay}
                if($objGPO.Enabled -ne $true) { $strDisplay = 'DIS-' + $strDisplay}
                $strExport = "$strFolderPath\$($strDisplay).html"
                $strExport = $strExport.Replace('/',' ')
                Write-Host "Exporting Report for $($objGPO.DisplayName) to $strExport" -ForegroundColor Green
                Get-GPOReport -Guid $objGPO.GPOId -ReportType 'Html' -Path $strExport
            }
        
        }
    }
}

function Get-AllADReplicationSites
{

    $ADSites = @{}

    $AllSites = Get-ADReplicationSite -Filter *

    foreach($ADSite in $AllSites)
    {
            $NewSite = [PSCustomObject]@{
            id = $ADSite.ObjectGUID
            name = $ADSite.Name
            fill = $contentFill
            stroke = $contentStroke
            shape = $contentShape
            refs = @()
        }

        $ADSites.Add($NewSite.id,$NewSite)
    }

    return $ADSites

}

function Get-ADSiteReplicationTree
{
    [CmdletBinding()]
    Param (
    [parameter(Mandatory=$true,ValueFromPipeline=$true)]
    [object] $Site,
    [parameter(Mandatory=$true)]
    [hashtable] $SiteList,
    [parameter(Mandatory=$true)]
    $ProcessedLinks #List object
    )
     
    # Get all replication links where this site belongs to
    $ReplicationLinks = Get-ADReplicationSiteLink -Filter "SitesIncluded -eq '$($Site.DistinguishedName)'"

    # Process all the links and sites that those links connect
    # We need to make sure we only process each link and site once, as otherwise we could create a loopback recursion.
    foreach($Link in $ReplicationLinks)
    {
            # Add this link to the list of processed links. This will prevent this link from being processed multiple times (and will eventually stop the recursion when all links have been processed once).
            $ProcessedLinks += $Link.ObjectGUID

            # Go through all the sites included in this replication link
            foreach($SiteIncluded in $Link.SitesIncluded)
            {
                # Only process sites that are NOT the site we retrieved the replication links from. This will prevent a loop where the site refers to itself for processing.
                if($SiteIncluded -ne $Site.DistinguishedName)
                {
                    # Get details of the site
                    $LinkedSite = Get-ADReplicationSite -Identity $SiteIncluded

                    # Since we need a structure where child objects refer to parent objects, we need to check whether the site entry for the linked site contains a link to the current site.
                    # If it does, we skip the site because this site has already been discovered. This will prevent loopbacks in the tree.
                    if($SiteList[$LinkedSite.ObjectGUID].refs -notcontains $Site.ObjectGUID)
                    {
                        # Link the current site as parent of the linked site
                        $SiteList[$LinkedSite.ObjectGUID].refs += $Site.ObjectGUID
                        Write-Verbose "$($Site.Name) replicating to $($LinkedSite.Name)"

                        # Get the replication tree from the linked site (we call ourselves recursively)
                        Get-ADSiteReplicationTree -Site $LinkedSite -SiteList $SiteList -ProcessedLinks $ProcessedLinks
                    }
                }
            }
    }
}

function Get-ADSiteReplicationDiagram
{

    [CmdletBinding()]
    Param (
    [parameter(Mandatory=$true,ValueFromPipeline=$true)]
    [string] $OutFile
    )


    $ADSites = Get-AllADReplicationSites

    $ProcessedLinks = New-Object System.Collections.Generic.List[string]

    Add-Content $OutFile '## Hello World
    # label: %site%
    # style: shape=%shape%;fillColor=%fill%;strokeColor=%stroke%;
    # namespace: csvimport-
    # connect: {"from":"refs", "to":"id", "style": "rounded=0;endArrow=none;endFill=0;startArrow=none;startFill=0;jumpStyle=sharp;"}
    # width: auto
    # height: auto
    # padding: 15
    # ignore: id,shape,fill,stroke,refs
    # nodespacing: 40
    # levelspacing: 100
    # edgespacing: 40
    # layout: auto
    ## CSV starts under this line'

    Add-Content $OutFile "id,site,fill,stroke,shape,refs"

    $contentFill = "#dae8fc"
    $contentStroke = "#6c8ebf"
    $contentShape = "rectangle"

    $RootSite = (Get-ADReplicationSite -Filter *)[0]
    $ListedSites += $RootSite.Name

    Get-ADSiteReplicationTree -Site $RootSite -SiteList $ADSites -ProcessedLinks $ProcessedLinks

    foreach($SiteID in $ADSites.Keys)
    {
        $id = $ADSites[$SiteID].id
        $name = $ADSites[$SiteID].name
        $fill = $ADSites[$SiteID].fill
        $stroke = $ADSites[$SiteID].stroke
        $shape = $ADSites[$SiteID].shape
        $reflist = $ADSites[$SiteID].refs -join ','
    
        Add-Content $OutFile "$id,$name,$fill,$stroke,$shape,$reflist"
    }


}

# Get all domains from the forest, some key information about them and the nearest domain controller
function Get-ForestDomains {

    $Domains = @()

    $LocalSite = Get-ADReplicationSite
    
    $ADForest = Get-ADForest
    
    foreach($DNSDomain in $ADForest.Domains)
    {
        $ADDomain = Get-ADDomain -Identity $DNSDomain
        $DomainController = Get-ADDomainController -SiteName $LocalSite.Name -DomainName $ADDomain.Name -ForceDiscover -NextClosestSite

        $DomainObject = New-Object -TypeName PSObject
        $DomainObject | Add-Member -Name 'DNSDomain' -MemberType NoteProperty -Value $DNSDomain
        $DomainObject | Add-Member -Name 'DistinguishedName' -MemberType NoteProperty -Value $ADDomain.DistinguishedName
        $DomainObject | Add-Member -Name 'NetBIOSName' -MemberType NoteProperty -Value $ADDomain.NetBIOSName
        $DomainObject | Add-Member -Name 'DomainControllerFQDN' -MemberType NoteProperty -Value $DomainController.HostName[0]
        $DomainObject | Add-Member -Name 'ParentDomain' -MemberType NoteProperty -Value $ADDomain.ParentDomain
        $DomainObject | Add-Member -Name 'PDCEmulator' -MemberType NoteProperty -Value $ADDomain.PDCEmulator

        $Domains += $DomainObject
       
    }

    $Domains

}

# Get ADDomain object from a distinguished name
function Get-DomainFromDN {
    [CmdletBinding()]
    Param (
    [parameter(Mandatory=$true,ValueFromPipeline=$true)]
    [string] $ObjectDN
    )

    $DomainDN = ""

    $DNArray = $ObjectDN.Split(",")
    foreach($Element in $DNArray)
    {
        if($Element.Substring(0,2) -eq "DC")
        {
            $DomainDN += "$Element,"
        }
    }

    # Remove the trailing comma
    $DomainDN = $DomainDN.Substring(0,$DomainDN.Length -1)

    $Domain = Get-ADDomain -Identity $DomainDN

    return $Domain

}

# Get the ADDomain object for any AD object
function Get-ObjectDomain {
    [CmdletBinding()]
    Param (
    [parameter(Mandatory=$true,ValueFromPipeline=$true)]
    [object] $ADObject
    )

    return($ADObject.DistinguishedName | Get-DomainFromDN)
}

Export-ModuleMember Get-ADGroupEnabledCount
Export-ModuleMember Get-AllADGroups
Export-ModuleMember Get-NestedGroups
Export-ModuleMember Get-ADObjectCountByOU
Export-ModuleMember Get-ADObjectContainer
Export-ModuleMember Get-ADContainerFromCN
Export-ModuleMember Get-ADObjectDate
Export-ModuleMember Get-GPLinks
Export-ModuleMember Get-DomainGPOReport
Export-ModuleMember New-ADOUPath
Export-ModuleMember GEt-AllGPOsReport
Export-ModuleMember Get-AllADReplicationSites
Export-ModuleMember Get-ADSiteReplicationTree
Export-ModuleMember Get-ADSiteReplicationDiagram
Export-ModuleMember Get-DomainFromDN
Export-ModuleMember Get-ForestDomains
Export-ModuleMember Get-ObjectDomain
