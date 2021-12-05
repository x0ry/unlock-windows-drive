# unlock-windows-drive
#If you're reading a hard drive from a separate windows system, you might run into file ownership conflicts.  This script resolves this by setting the ownership of the drive contents to "Everyone"

#Unlock Directories
#P/Invoke'd C# code to enable required privileges to take ownership and make changes when NTFS permissions are lacking
$AdjustTokenPrivileges = @"
using System;
using System.Runtime.InteropServices;
 public class TokenManipulator
 {
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
  ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
  [DllImport("kernel32.dll", ExactSpelling = true)]
  internal static extern IntPtr GetCurrentProcess();
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr
  phtok);
  [DllImport("advapi32.dll", SetLastError = true)]
  internal static extern bool LookupPrivilegeValue(string host, string name,
  ref long pluid);
  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  internal struct TokPriv1Luid
  {
   public int Count;
   public long Luid;
   public int Attr;
  }
  internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
  internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
  internal const int TOKEN_QUERY = 0x00000008;
  internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
  public static bool AddPrivilege(string privilege)
  {
   try
   {
    bool retVal;
    TokPriv1Luid tp;
    IntPtr hproc = GetCurrentProcess();
    IntPtr htok = IntPtr.Zero;
    retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
    tp.Count = 1;
    tp.Luid = 0;
    tp.Attr = SE_PRIVILEGE_ENABLED;
    retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
    retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    return retVal;
   }
   catch (Exception ex)
   {
    throw ex;
   }
  }
  public static bool RemovePrivilege(string privilege)
  {
   try
   {
    bool retVal;
    TokPriv1Luid tp;
    IntPtr hproc = GetCurrentProcess();
    IntPtr htok = IntPtr.Zero;
    retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
    tp.Count = 1;
    tp.Luid = 0;
    tp.Attr = SE_PRIVILEGE_DISABLED;
    retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
    retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    return retVal;
   }
   catch (Exception ex)
   {
    throw ex;
   }
  }
 }
"@
add-type $AdjustTokenPrivileges

Get-ChildItem -Recurse -Directory | foreach-object  { write-host ("{0}" -f $_.FullName)

$Folder = Get-Item $_.FullName
#Activate necessary admin privileges to make changes without NTFS perms
[void][TokenManipulator]::AddPrivilege("SeRestorePrivilege") #Necessary to set Owner Permissions
[void][TokenManipulator]::AddPrivilege("SeBackupPrivilege") #Necessary to bypass Traverse Checking
[void][TokenManipulator]::AddPrivilege("SeTakeOwnershipPrivilege") #Necessary to override FilePermissions

#Obtain a copy of the initial ACL
$NewOwnerACL = New-Object System.Security.AccessControl.DirectorySecurity
#Establish the folder as owned by BUILTIN\Administrators, guaranteeing the following ACL changes can be applied
$Admin = New-Object System.Security.Principal.NTAccount("Everyone")
$NewOwnerACL.SetOwner($Admin)
#Merge the proposed changes (new owner) into the folder's actual ACL
$Folder.SetAccessControl($NewOwnerACL)
}

#Unlock Files
Get-ChildItem -Path "./*.*" -Recurse | ForEach-Object {
    icacls.exe $_.FullName /setowner everyone
    icacls.exe $_.FullName /grant 'everyone:rw'
}
