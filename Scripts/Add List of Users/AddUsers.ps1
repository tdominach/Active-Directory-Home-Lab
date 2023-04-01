<# 
    Written by: Thomas Dominach

    This script streamlines the creation of multiple users accounts. It also has the option of letting the admin specify each users group. It takes a txt file
    filled with client names as input and adds them to the domain. To specfiy the group of a new user the admin simply needs to add the group name next to the
    corrisponding user in the file.

    Example TXT File:
    Steven McGregor       <---- Each line contains the new users fullname. 
    Sarah Smith-HelpDesk  <---- Optionally a group name can be added on the same line seperated by a single '-' w/ no spaces.   
    Paul Grimes-SalesUser
    Marie Gray      
#>
Import-Module ActiveDirectory

$UserList = Get-Content .\newUsers.txt # newUsers.txt must be in the same directory/folder as AddUser.ps1

#Returns true if the given password meets Microsoft's password complexity requirements 
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

#Returns true if the given group name exist in the domain.
function Confirm-GroupName {
    Param($Group)
    try {
        Get-ADGroup -Identity $Group
        return $true
    }
    catch {
        return $false
    }
}

#Array that contains the console output for admin. Establishes the Username, Group, and Password columns.
$output = "Username", "Group", "Password", "------------------", "------------------", "------------------"


$DNSRoot = (Get-ADDomain -Current LoggedOnUser).DNSRoot 
$DCAttributes = $DNSRoot.Split(".")
$UserPath = "OU=_USERS" + ",DC=" + $DCAttributes[0] + ",DC=" + $DCAttributes[1] # Specifies the OU users will be added to (can be changed to accommodate other domains)

foreach ($line in $UserList) {
    
    $userInfo = $line.Split("-")
    $FullName = $userInfo[0]
    $GroupName = $userInfo[1]
    $NameList = $FullName.Split(" ") 
    $UserPrinName = $NameList[0].Substring(0, 1) + $NameList[1] + "@" + $DNSRoot
    $SamAccName = $NameList[0].Substring(0, 1) + $NameList[1]
    $Password = New-RandomPassword
    $SecPass = ConvertTo-SecureString -String $Password -AsPlainText -Force #Need to convert password to secure string for the New-ADUser command.

    New-ADUser -Name $Fullname -GivenName $NameList[0] -Surname $NameList[1] -UserPrincipalName $UserPrinName -SamAccountName $SamAccName -DisplayName $FullName -AccountPassword $SecPass -Enabled $true -Path "$UserPath"

    if (Confirm-GroupName($GroupName) -eq $true) { 
        Add-ADGroupMember -Identity $GroupName -Members $SamAccName 
    }
    else {
  
        if ($GroupName -eq $null) {
            Write-Host "GROUP NAME NOT GIVEN:" $Fullname "will be added to the domain without a group." -ForegroundColor Red
        }
        else {
            Write-Host "INVALID GROUP NAME: Group name" $GroupName "does not exist within the domain." $Fullname "will be added to the domain without a group." -ForegroundColor Red
        }
        $GroupName = "None" 
         
    }#Else statement handles any errors thrown when group name is not present or valid.
    
    Set-ADUser -Identity $username -ChangePasswordAtLogon $true #Forces user to change their password on next logon.
    
    #Add username, group name, and password to the output array.
    $output += $SamAccName
    $output += $GroupName
    $output += $Password
    
    Write-Host $Fullname "successfully added to domain." -ForegroundColor Green
}

$output | Select-Object @{Name = 'String'; Expression = { $_ } } | Format-Wide String -Column 3 # Creates three columns for 'Username', 'Group', and 'Password'
