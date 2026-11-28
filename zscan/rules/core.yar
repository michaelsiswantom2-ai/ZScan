/*
  Starter YARA rules for zscan. Defensive / educational use.
  Add your own .yar files to this folder or pass --rules <dir>.
*/

rule EICAR_Test_File
{
    meta:
        description = "EICAR antivirus test file (harmless industry test string)"
        severity = 5
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule UPX_Packed
{
    meta:
        description = "Executable packed with UPX (Windows or Linux)"
        severity = 2
        group = "packing"    // one trait with zscan's own packer checks; counted once
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $sig  = "UPX!"
        $info = "This file is packed with the UPX executable packer"
        $id   = "$Id: UPX"
    condition:
        (uint16(0) == 0x5A4D and 2 of ($upx0, $upx1, $sig))
        or (uint32(0) == 0x464C457F and $sig and 1 of ($info, $id))
}

rule Ransomware_Commands
{
    meta:
        description = "Commands commonly run by ransomware to block recovery"
        severity = 4
    strings:
        $a = "vssadmin delete shadows" nocase
        $b = "wmic shadowcopy delete" nocase
        $c = "bcdedit /set {default} recoveryenabled no" nocase
        $d = "wbadmin delete catalog" nocase
    condition:
        2 of them
}

rule Process_Injection_API_Strings
{
    meta:
        description = "Classic remote-thread injection API names present together"
        severity = 3
        group = "injection"  // the same trait as zscan's import-table check; counted once
    strings:
        $a = "VirtualAllocEx"
        $b = "WriteProcessMemory"
        $c = "CreateRemoteThread"
    condition:
        all of them
}

rule Office_Macro_AutoExec
{
    meta:
        description = "OLE document with auto-executing VBA macro plus shell call"
        severity = 3
    strings:
        $auto1 = "AutoOpen" nocase
        $auto2 = "Document_Open" nocase
        $auto3 = "Workbook_Open" nocase
        $exec1 = "Shell" nocase
        $exec2 = "WScript.Shell" nocase
        $exec3 = "CreateObject" nocase
    condition:
        uint32(0) == 0xE011CFD0 and any of ($auto*) and any of ($exec*)
}

rule Webshell_PHP_Eval
{
    meta:
        description = "PHP that evaluates decoded request data (common webshell shape)"
        severity = 4
    strings:
        $php = "<?php" nocase
        $e1 = /eval\s*\(\s*(base64_decode|gzinflate|str_rot13)\s*\(/ nocase
        $e2 = /(eval|assert|system|passthru)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
    condition:
        $php and any of ($e*)
}
