function Get-AADMFAState {

    [CmdletBinding()]
    Param (
    [parameter(Mandatory=$true,HelpMessage='MsolUser objects to obtain MFA status from',ValueFromPipeline=$true)]
    [object] $objMsolUser
    )

    begin {
        $listReturn = New-Object Collections.Generic.List[Object]
    }

    process {

        $Count = $objMsolUser.StrongAuthenticationRequirements.Count
        $Methods = $objMsolUser.StrongAuthenticationMethods.Count

        if($Count -eq 1)
        {
            $State = $objMsolUser.StrongAuthenticationRequirements[0].State

        } else { 
            $State = "Disabled"
        }

        $objUser = @(
            Country = $objMsolUser.Country
            City = $objMsolUser.City
            UPN = $objMsolUser.userPrincipalName
            Office = $objMsolUser.Office
            State = $State
            MethodCount = $Methods
        )


        $listReturn.Add($objUser)
    }

    end {
        return $listReturn
    }
}

Export-ModuleMember Get-AADMFAState