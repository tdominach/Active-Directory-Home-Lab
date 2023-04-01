<#
    Written by: Thomas Dominach

    This script seamlessly resets multiple users passwords with a txt file filled their usernames and
    outputs a table with each users new password.

#>
Import-Module ActiveDirectory

$UserList = Get-Content .\users.txt # users.txt must contain a list of usernames(SamAccountName) from the users who need their passwords reset. 

#Function that returns true if the parameter meets Microsoft's password complexity requirements 
function Confirm-PassComplexity {
    Param($Pass)

    if (($Pass -cmatch "[A-Z\p{Lu}\s]") `
            -and ($Pass -cmatch "[a-z\p{Ll}\s]") `
            -and ($Pass -match "[\d]") `
            -and ($Pass -match "[^\w]")) {
        return $True
    }
    else {
        return $false
    }
}

#Generates and returns a random password that is compatable with the domains password policy.
function New-RandomPassword {
    Param($Username)

    Add-Type -AssemblyName 'System.Web'
    $PassPolicy = Get-ADDefaultDomainPasswordPolicy
    $length = $PassPolicy.MinPasswordLength
    $isComplex = $false
    
    do {
        $password = [System.Web.Security.Membership]::GeneratePassword($length, 1)
    
        if (Confirm-PassComplexity($password) -eq $True) {
            $isComplex = $True
        }
    } while ($isComplex -eq $false) #Do-While loop keeps generating new passwords until it meets complexity requirements 
    
    return $password
}

$output = "SamAccountName", "New Password", "------------------", "------------------"

foreach ($username in $UserList) {
    
    $NewPassword = New-RandomPassword($username)
    Set-ADAccountPassword -Identity $username -Reset -NewPassword(ConvertTo-SecureString -AsPlainText $NewPassword -Force) # Resets user's password and replaces it with the new one that was generated
    Set-ADUser -Identity $username -ChangePasswordAtLogon $true # Forces user to change their password when they logon.
    $output += $username
    $output += $NewPassword
}

$output | Select-Object @{Name = 'String'; Expression = { $_ } } | Format-Wide String -Column 2 # Creates two columns for 'SamAccountName' and 'New Password'