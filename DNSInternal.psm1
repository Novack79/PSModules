# Get all DNS Servers for an Active Directory Domain
function Get-AllDNSServers
{
    <#
    Written by Pekka Saarimaa

    .SYNOPSIS
        Get all DNS servers for a given Active Directory domain.
    .DESCRIPTION
        .
    .EXAMPLE
        Get-AllDNSServers -Domain northwind.corp -TestConnection
    .PARAMETER Domain
        AD domain to query.
    .PARAMETER TestConnection
        If included, will ping the DNS server before trying to connect. Can reduce unnecessary timeouts and make the function faster.
    .INPUTS
    .OUTPUTS
        Array of the DNS Server objects returned by Get-DNSServer.
    .NOTES
    .LINK
    #>

    Param(
    [parameter(Mandatory=$true,HelpMessage='FQDN of Active Directory domain to be queried for DNS servers.')]
    [String] $Domain,
    [parameter(HelpMessage='If set, will ping the DNS servers before querying them for properties.')]
    [switch] $TestConnection
    )

    $arrDNSServers = (Get-DnsServerResourceRecord -ZoneName $Domain -RRType NS).RecordData.NameServer
    $arrReturn = @()

    foreach($strDNSServer in $arrDNSServers)
    {
        if ($TestConnection)
        {
            if(Test-Connection -ComputerName $strDNSServer -Quiet)
            {
                $arrReturn += Get-DNSServer -ComputerName $strDNSServer
            } else {
                Write-Warning "Server $strDNSServer was not reachable, skipping..."
            }
        } else {
            $arrReturn += Get-DNSServer -ComputerName $strDNSServer
        }
    }

    return $arrReturn

}

function Get-DnsForwarders
{
    <#
    Written by Pekka Saarimaa

    .SYNOPSIS
        Get all DNS Forwarders for given DNS Servers
    .DESCRIPTION
        .
    .EXAMPLE
        Get-DNSForwarders -DNSServer $DNSServer
    .EXAMPLE
        $Forwarders = ($DNSServers | Get-DNSForwarders)
    .PARAMETER DNSServer
        Array or list of DNS Servers to query. Accepts parameter from pipeline.
    .INPUTS
    .OUTPUTS
        List of PS objects with [string]Server and [string]Forwarder properties.
    .NOTES
    .LINK
    #>
    [CmdletBinding()]
    Param(
    [parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage='List of PSobjects from Get-DNSServer.')]
    $DNSServer
    )

    begin {
        $listReturn = New-Object Collections.Generic.List[Object]
    }

    process {
        $arrForwarders = $DNSServer.ServerForwarder.IPAddress

        foreach($strForwarder in $arrForwarders)
        {
            $objForwarder = New-Object -TypeName psobject
            $objForwarder | Add-Member -MemberType NoteProperty -Name Server -Value $DNSServer.ServerSetting.ComputerName
            $objForwarder | Add-Member -MemberType NoteProperty -Name Forwarder -Value $strForwarder
            $listReturn.Add($objForwarder)
        }
    }

    end {
        return $listReturn
    }

}

function Get-DnsZones
{
    <#
    Written by Pekka Saarimaa

    .SYNOPSIS
        Get all DNS Zones for given DNS Servers
    .DESCRIPTION
        .
    .EXAMPLE
        Get-DNSZones -DNSServer $DNSServer
    .EXAMPLE
        $Zones = (Get-AllDNSServers | Get-DNSZones)
    .PARAMETER DNSServer
        Array or list of DNS Servers to query. Accepts parameter from pipeline.
    .INPUTS
    .OUTPUTS
        List of PS objects with [string]Server and [string]Zone properties.
    .NOTES
    .LINK
    #>
    [CmdletBinding()]
    Param(
    [parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage='List of PSobjects from Get-DNSServer.')]
    $DNSServer
    )

    begin {
        $listReturn = New-Object Collections.Generic.List[Object]
    }

    process {

        $arrZones = $DNSServer.ServerZone.ZoneName

        foreach ($strZone in $arrZones)
        {
            $objZone = New-Object -TypeName psobject
            $objZone | Add-Member -MemberType NoteProperty -Name Server -Value $DNSServer.ServerSetting.ComputerName
            $objZone | Add-Member -MemberType NoteProperty -Name DnsZone -Value $strZone
            $listReturn.Add($objZone)
        }

    }

    end {
        return $listReturn
    }
}

function Get-DNSZoneRecordsFromServer
{
    <#
    Written by Pekka Saarimaa

    .SYNOPSIS
        Get all DNS Records for a list of [string]Server and [string]Zone objects.
    .DESCRIPTION
        .
    .EXAMPLE
        Get-AllDNSServers | Get-DNSZones | Get-DNSZoneRecordsFromServer -RecordType ALL_RECORDS
    .EXAMPLE
        Get-DNSServer -ComputerName localhost | Get-DNSZones | Get-DNSZoneRecordsFromServer -RecordType A,CNAME
    .PARAMETER DNSServer
        A list of DNS Servers and zones to query. Accepts parameter from pipeline as outputted by Get-DNSZones function.
    .PARAMETER RecordType
        An array of the type(s) of DNS records to obtain. "ALL_RECORDS" can be used to include all supported types.
    .INPUTS
    .OUTPUTS
        List of object record PS objects (from Get-DNSServerResourceRecord), with added Server and Zone properties.
        The value of the record can depend on the type of DNS record, so there are additional properties for each record type.
    .NOTES
    .LINK
    #>
    Param(
    [parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage='List of PSObjects with [string]Server,[string]DnsZone properties. Accepts output of Get-DNSZones.')]
    $ServerZone,

    [Parameter(Mandatory=$true, HelpMessage='DNS record types to obtain. Use ALL_RECORDS to obtain all supported record types.')]
    [ValidateSet('A','AAAA','CNAME','NS','TXT','MX','SOA','SRV','PTR','ALL_RECORDS')]
    [String[]]$RecordType
    )

    begin {
        $listReturn = New-Object Collections.Generic.List[Object]
    }

    process {

        $listRecords = Get-DnsServerResourceRecord -ComputerName $ServerZone.Server -ZoneName $ServerZone.DnsZone

        # Add the server and zone to each record so that when records are combined to a single array from multiple servers,
        # the distinction between same records from different servers is maintained 
        foreach($objRecord in $listRecords)
        {
            try {
                $objRecord | Add-Member -MemberType NoteProperty -Name DnsZone -Value $ServerZone.DnsZone
                $objRecord | Add-Member -MemberType NoteProperty -Name ServerName -Value $ServerZone.Server

                # Add placeholders for recordtype specific fields
                $objRecord | Add-Member -MemberType NoteProperty -Name NS_NameServer -Value $null
                $objRecord | Add-Member -MemberType NoteProperty -Name CNAME_HostNameAlias -Value $null
                $objRecord | Add-Member -MemberType NoteProperty -Name A_IPv4Addr -Value $null
                $objRecord | Add-Member -MemberType NoteProperty -Name SRV_DomainName -Value $null
                $objRecord | Add-Member -MemberType NoteProperty -Name SRV_Port -Value $null
                $objRecord | Add-Member -MemberType NoteProperty -Name SRV_Priority -Value $null
                $objRecord | Add-Member -MemberType NoteProperty -Name SRV_Weight -Value $null
                $objRecord | Add-Member -MemberType NoteProperty -Name SOA_ExpireLimit -Value $null
                $objRecord | Add-Member -MemberType NoteProperty -Name SOA_TTL -Value $null
                $objRecord | Add-Member -MemberType NoteProperty -Name SOA_PrimaryServer -Value $null
                $objRecord | Add-Member -MemberType NoteProperty -Name SOA_RefreshInterval -Value $null
                $objRecord | Add-Member -MemberType NoteProperty -Name SOA_ResponsiblePerson -Value $null
                $objRecord | Add-Member -MemberType NoteProperty -Name SOA_RetryDelay -Value $null
                $objRecord | Add-Member -MemberType NoteProperty -Name AAAA_IPv6Addr -Value $null
                $objRecord | Add-Member -MemberType NoteProperty -Name TXT_DescriptiveText -Value $null
                $objRecord | Add-Member -MemberType NoteProperty -Name MX_MailExchange -Value $null
                $objRecord | Add-Member -MemberType NoteProperty -Name MX_Preference -Value $null
                $objRecord | Add-Member -MemberType NoteProperty -Name PTR_PtrDomainName -Value $null

                # The value of the DNS entry is recoded in a RecordData object. The object can have 1 or more properties depending
                # on the type of DNS record.
                if($objRecord.RecordData.CimClass.CimClassName -eq 'DnsServerResourceRecordNS' -and ($RecordType -contains 'ALL_RECORDS' -or $RecordType -contains 'NS'))
                {
                    $objRecord.NS_NameServer = $objRecord.RecordData.NameServer
                    $listReturn.Add($objRecord)
                    continue
                }

                if($objRecord.RecordData.CimClass.CimClassName -eq 'DnsServerResourceRecordA' -and ($RecordType -contains 'ALL_RECORDS' -or $RecordType -contains 'A'))
                {
                    $objRecord.A_IPv4Addr = $objRecord.RecordData.IPv4Address
                    $listReturn.Add($objRecord)
                    continue
                }

                if($objRecord.RecordData.CimClass.CimClassName -eq 'DnsServerResourceRecordCName' -and ($RecordType -contains 'ALL_RECORDS' -or $RecordType -contains 'CNAME'))
                {
                    $objRecord.CNAME_HostNameAlias = $objRecord.RecordData.HostNameAlias
                    $listReturn.Add($objRecord)
                    continue
                }

                if($objRecord.RecordData.CimClass.CimClassName -eq 'DnsServerResourceRecordTxt' -and ($RecordType -contains 'ALL_RECORDS' -or $RecordType -contains 'PTR'))
                {
                    $objRecord.PTR_PtrDomainName = $objRecord.RecordData.PtrDomainName
                    $listReturn.Add($objRecord)
                    continue
                }
            
                if($objRecord.RecordData.CimClass.CimClassName -eq 'DnsServerResourceRecordTxt' -and ($RecordType -contains 'ALL_RECORDS' -or $RecordType -contains 'TXT'))
                {
                    $objRecord.TXT_DescriptiveText = $objRecord.RecordData.DescriptiveText
                    $listReturn.Add($objRecord)
                    continue
                }

                if($objRecord.RecordData.CimClass.CimClassName -eq 'DnsServerResourceRecordMx' -and ($RecordType -contains 'ALL_RECORDS' -or $RecordType -contains 'MX'))
                {
                    $objRecord.MX_MailExchange = $objRecord.RecordData.MailExchange
                    $objRecord.MX_Preference = $objRecord.RecordData.Preference
                    $listReturn.Add($objRecord)
                    continue
                }

                 if($objRecord.RecordData.CimClass.CimClassName -eq 'DnsServerResourceRecordSrv' -and ($RecordType -contains 'ALL_RECORDS' -or $RecordType -contains 'SRV'))
                {
                    $objRecord.SRV_DomainName = $objRecord.RecordData.DomainName
                    $objRecord.SRV_Port = $objRecord.RecordData.Port
                    $objRecord.SRV_Priority = $objRecord.RecordData.Priority
                    $objRecord.SRV_Weight = $objRecord.RecordData.Weight
                    $listReturn.Add($objRecord)
                    continue
                }

                if($objRecord.RecordData.CimClass.CimClassName -eq 'DnsServerResourceRecordSoa' -and ($RecordType -contains 'ALL_RECORDS' -or $RecordType -contains 'SOA'))
                {
                    $objRecord.SOA_ExpireLimit = $objRecord.RecordData.ExpireLimit
                    $objRecord.SOA_TTL = $objRecord.RecordData.MinimumTimeToLive
                    $objRecord.SOA_PrimaryServer = $objRecord.RecordData.PrimaryServer
                    $objRecord.SOA_RefreshInterval = $objRecord.RecordData.RefreshInterval
                    $objRecord. SOA_ResponsiblePerson = $objRecord.RecordData.ResponsiblePerson
                    $objRecord.SOA_RetryDelay = $objRecord.RecordData.RetryDelay
                    $listReturn.Add($objRecord)
                    continue
                }

                if($objRecord.RecordData.CimClass.CimClassName -eq 'DnsServerResourceRecordAAAA' -and ($RecordType -contains 'ALL_RECORDS' -or $RecordType -contains 'AAAA'))
                {
                    $objRecord.AAAA_IPv6Addr = $objRecord.RecordData.IPv6Address
                    $listReturn.Add($objRecord)
                    continue
                }

            } catch {
                $ErrorMessage = $_.Exception.Message
                $FailedItem = $_.Exception.ItemName
                Write-Host "$($objRecord.DistinguishedName) - $($ServerZone.Server) - $($ServerZone.DnsZone) - $ErrorMessage"
            }
        }
    }

    end {
        return $listReturn
    }
}

Export-ModuleMember -Function Get-AllDNSServers
Export-ModuleMember -Function Get-DNSForwarders
Export-ModuleMember -Function Get-DNSZones
Export-ModuleMember -Function Get-DNSZoneRecordsFromServer
Export-ModuleMember -Function Get-AllDNSZoneRecordsFromServer
