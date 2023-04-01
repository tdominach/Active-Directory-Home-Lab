<#
    Written by: Thomas Dominach

    This script performs a password reset for a single user by providing a valid username(SamAccountName).

#>
Import-Module ActiveDirectory

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

#Returns true if client's username is in the domain.
function Confirm-Username {
    Param($username)

    try {
        Get-ADUser -Identity $username
        return $true
    }
    catch {
        return $false
    }
}

#Array that contains the console output for admin. Establishes the Username and New Password columns.
$output = "Username", "New Password", "------------------", "------------------"

Write-Host "This script will perform a password reset for a client's user account. Follow the prompt to continue."
do {
    $username = Read-Host -Prompt "Enter client's username"
    if ($(Confirm-Username($username)) -eq $false) {
        Write-Host "User account not found. Please enter a valid username." -ForegroundColor Red
    }
    else {
        $NewPassword = New-RandomPassword($username)
        Set-ADAccountPassword -Identity $username -Reset -NewPassword(ConvertTo-SecureString -AsPlainText $NewPassword -Force) # Resets user's password and replaces it with the new one that was generated
        Set-ADUser -Identity $username -ChangePasswordAtLogon $true # Forces user to change their password on next logon.
        
        #Add username and the new password to the output array.
        $output += $username
        $output += $NewPassword

        Write-Host "Password Reset successful!" -ForegroundColor Green
    }
} while ($(Confirm-Username($username)) -eq $false)


$output | Select-Object @{Name = 'String'; Expression = { $_ } } | Format-Wide String -Column 2 # Creates two columns for 'SamAccountName' and 'New Password'

