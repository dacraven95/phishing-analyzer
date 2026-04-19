rule OfficeMacro_AutoOpen
{
    meta:
        description = "Office document contains auto-executing macro"
        author      = "phish-analyzer"
        severity    = "critical"
        attack_ids  = "T1566.001,T1204.002,T1137.001,T1059.005"
        category    = "office_macro"

    strings:
        $vba1 = "Auto_Open"   nocase
        $vba2 = "AutoOpen"    nocase
        $vba3 = "AutoExec"    nocase
        $vba4 = "Document_Open" nocase
        $vba5 = "Workbook_Open" nocase
        $vba6 = "Auto_Close"  nocase

    condition:
        any of them
}

rule OfficeMacro_Shell_Execution
{
    meta:
        description = "Office macro invokes shell/process execution"
        author      = "phish-analyzer"
        severity    = "critical"
        attack_ids  = "T1566.001,T1204.002,T1059.001,T1059.005"
        category    = "office_macro"

    strings:
        $shell1 = "Shell("       nocase
        $shell2 = "WScript.Shell" nocase
        $shell3 = "powershell"    nocase
        $shell4 = "cmd.exe"       nocase
        $shell5 = "CreateObject"  nocase
        $shell6 = "Win32_Process" nocase

    condition:
        2 of them
}