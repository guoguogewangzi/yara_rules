rule HackTool_Proxy_ASPX_reGeorg_v1_0_001
{
	meta:

		// 规则创建时间
		date_created = "2021-10-25"
		// 规则最后一次修改时间
		date_modified = "2021-10-25"
		// 规则最后一次修改人（邮箱）
		author = "zhangxin2@antiy.cn"
		// 规则匹配的样本的MD5
		md5 = "d6a82b866f7f9e1e01bf89c3da106d9d"
		// 修改完一次 加一
		rev = 1
		
		// black:恶意的，grey:疑似恶意的，white:安全的
		judge = "black"
		
		// 参考 5.5 家族名称/软件名称 
		// 为了兼容老的规则
		// 比如： fscan mimikatz Behinder YuJian CS
		family = "reGeorg"

		// 没有中文名称可不填写 ,有的话写中文.比如 冰蝎 灰鸽子 御剑 永恒之蓝
		cnAliase = ""

		// 该部分参考5.3 核心行为的定义
		// 为了兼容老的规则
		threattype="Proxy"

		// 为了兼容老的规则
		// <分类名称>[核心行为]/<环境前缀>.<家族名称/软件名称>.<家族变种号/软件版本/唯一标识符>
		threatname="HackTool[Proxy]/ASPX.reGeorg.v1_0_001"
        

	strings:
		$input_sa1 = "Request.QueryString.Get" fullword nocase wide ascii
		$input_sa2 = "Request.Headers.Get" fullword nocase wide ascii
		$sa1 = "AddressFamily.InterNetwork" fullword nocase wide ascii
		$sa2 = "Response.AddHeader" fullword nocase wide ascii
		$sa3 = "Request.InputStream.Read" nocase wide ascii
		$sa4 = "Response.BinaryWrite" nocase wide ascii
		$sa5 = "Socket" nocase wide ascii
        $georg = "Response.Write(\"Georg says, 'All seems fine'\")"
	
		//strings from private rule capa_asp
		$tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
		$tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
		$tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
		$tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
		$tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
		$tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
		$tagasp_long10 = "<%@ " wide ascii
        // <% eval
		$tagasp_long11 = /<% \w/ nocase wide ascii
		$tagasp_long12 = "<%ex" nocase wide ascii
		$tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>           
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
		$tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

		$tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
		$tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword
        
	
	condition:
		filesize < 300KB and ( 
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize ) 
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize ) 
                )
            ) 
        ) and not ( 
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0 
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        ) 
		)
		and 
		( $georg or 
		( all of ( $sa* ) and any of ( $input_sa* ) ) )
}