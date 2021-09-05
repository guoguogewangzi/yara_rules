rule Hackingteam_Elevator_DLL 
{

    meta:
        description = "Hacking Team Disclosure Sample - file elevator.dll"
        author = "Florian Roth"
        reference = "http://t.co/EG0qtVcKLh"
        date = "2015-07-07"
        hash = "b7ec5d36ca702cc9690ac7279fd4fea28d8bd060"
   
    strings:
        $s1 = "\\sysnative\\CI.dll" fullword ascii
        $s2 = "setx TOR_CONTROL_PASSWORD" fullword ascii
        $s3 = "mitmproxy0" fullword ascii
        $s4 = "\\insert_cert.exe" fullword ascii
        $s5 = "elevator.dll" fullword ascii
        $s6 = "CRTDLL.DLL" fullword ascii
        $s7 = "fail adding cert" fullword ascii
        $s8 = "DownloadingFile" fullword ascii
        $s9 = "fail adding cert: %s" fullword ascii
        $s10 = "InternetOpenA fail" fullword ascii
   
    condition:
        uint16(0) == 0x5a4d and filesize < 1000KB and 6 of them
}

rule webshell_h4ntu_shell_powered_by_tsoi_  : webshell {
	meta:
		description = "Web Shell - file h4ntu shell [powered by tsoi].php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "06ed0b2398f8096f1bebf092d0526137"
	strings:
		$s0 = "  <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><b>Server Adress:</b"
		$s3 = "  <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><b>User Info:</b> ui"
		$s4 = "    <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><?= $info ?>: <?= "
		$s5 = "<INPUT TYPE=\"text\" NAME=\"cmd\" value=\"<?php echo stripslashes(htmlentities($"
	condition:
		all of them
}

rule HackTool_MSIL_Rubeus_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public Rubeus project."
        md5 = "66e0681a500c726ed52e5ea9423d2654"
        rev = 4
        author = "FireEye"
    strings:
        $typelibguid = "658C8B7F-3664-4A95-9572-A3E5871DFC06" ascii nocase wide
    condition:
        uint16(0) == 0x5A4D and $typelibguid
}