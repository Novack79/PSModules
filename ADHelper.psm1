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

Export-ModuleMember Get-ADGroupEnabledCount
Export-ModuleMember Get-AllADGroups
Export-ModuleMember Get-ADObjectCountByOU
Export-ModuleMember Get-ADObjectContainer
Export-ModuleMember Get-ADContainerFromCN
Export-ModuleMember Get-ADObjectDate
Export-ModuleMember Get-GPLinks

