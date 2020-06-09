function Get-DHCPv4Scopes
{
   [CmdletBinding()]
    Param(
    [parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage='List of DHCP Servers from Get-DhcpServerInDC')]
    $DHCPServer
    )

    begin {
        $listReturn = New-Object Collections.Generic.List[Object]
    }

    process {
        $arrScopes = Get-DHCPServerv4Scope -ComputerName $DHCPServer.DnsName
        foreach($objScope in $arrScopes)
        {
            $arrOptions =  Get-DhcpServerv4OptionValue -ComputerName $DHCPServer.DnsName -ScopeId "$($objScope.ScopeId)" -All

            if($arrOptions -ne $null)
            {
                foreach($objOption in $arrOptions)
                {

                    $strValues = $objOption.Value -join ','

                    $objScope = New-Object PSObject -Property @{
                        Server = $DHCPServer.DnsName
                        ServerIP = $DHCPServer.IPAddress
                        Name = $objScope.Name
                        SubnetMask = $objScope.SubnetMask
                        StartRange = $objScope.StartRange
                        EndRange = $objScope.EndRange
                        ScopeId = $objScope.ScopeId
                        OptionID = $objOption.OptionID
                        OptionName = $objOption.name
                        OptionValue =$strValues
                        OptionVendorClass = $objOption.VendorClass
                        OptionUserClass = $objOption.UserClass
                    }
                 }
             } else {
                $objScope = New-Object PSObject -Property @{
                    Server = $DHCPServer.DnsName
                    ServerIP = $DHCPServer.IPAddress
                    Name = $objScope.Name
                    SubnetMask = $objScope.SubnetMask
                    StartRange = $objScope.StartRange
                    EndRange = $objScope.EndRange
                    ScopeId = $objScope.ScopeId
                }
             }

             $listReturn.Add($objScope)
        }

        

    }

    end {
        return $listReturn
    }

}

function Get-DHCPv4ServerOptions
{
   [CmdletBinding()]
    Param(
    [parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage='List of DHCP Servers from Get-DhcpServerInDC')]
    $DHCPServer
    )

    begin {
        $listReturn = New-Object Collections.Generic.List[Object]
    }

    process {
        $arrOptions =  Get-DhcpServerv4OptionValue -ComputerName $DHCPServer.DnsName -All

        foreach($objOption in $arrOptions)
        {

            $strValues = $objOption.Value -join ','

            $objOption = New-Object PSObject -Property @{
                Server = $DHCPServer.DnsName
                ServerIP = $DHCPServer.IPAddress
                OptionID = $objOption.OptionID
                OptionName = $objOption.name
                OptionValue =$strValues
                OptionVendorClass = $objOption.VendorClass
                OptionUserClass = $objOption.UserClass
            }
         }
        

        $listReturn.Add($objOption)

    }

    end {
        return $listReturn
    }

}

Export-ModuleMember -Function Get-DHCPv4Scopes
Export-ModuleMember -Function Get-DHCPv4ServerOptions