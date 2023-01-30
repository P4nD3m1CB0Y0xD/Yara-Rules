rule LNK_Suspicious
{
  meta:
    description = "Yara rule to detect suspicious LNK files"
    author = "@P4nd3m1cb0y"
    date = "2023-01-27"

  strings:
    $lnk_file = { 4C 00 00 00 }
    $mini = { 30 9D 1? 00 }
    $ishidden = { 20 00 00 00 }
    $s1 = "Windows\\System32\\cmd.exe" ascii nocase
    $s2 = "Windows\\System32\\conhost.exe" ascii nocase
    $s3 = "/V/D/c" ascii nocase
    $s4 = "%ComSpec%" ascii nocase
    $s5 = "\\Windows\\System32\\WindowsPowerShell\\v?.?\\powershell.exe" ascii nocase

  condition:
    uint32(0) == 0x0000004c and 
    $lnk_file and $mini and 
    $ishidden and any of ($s*)
}
