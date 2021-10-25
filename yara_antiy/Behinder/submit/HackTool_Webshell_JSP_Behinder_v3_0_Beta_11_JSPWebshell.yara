rule HackTool_Webshell_JSP_Behinder_v3_0_Beta_11_JSPWebshell
{
	meta:
		// 规则创建时间
		date_created = "2021-09-06"
		// 规则最后一次修改时间
		date_modified = "2021-09-06"
		// 规则最后一次修改人（邮箱）
		author = "zhangxin2@antiy.cn"
		// 规则匹配的样本的MD5
		md5 = "e981219f6ba673e977c5c1771f86b189"
		// 修改完一次 加一
		rev = 1
		
		// black:恶意的，grey:疑似恶意的，white:安全的
		judge = "black"
		
		// 参考 5.5 家族名称/软件名称 
		// 为了兼容老的规则
		// 比如： fscan mimikatz Behinder YuJian CS
		family = "Behinder"

		// 没有中文名称可不填写 ,有的话写中文.比如 冰蝎 灰鸽子 御剑 永恒之蓝
		cnAliase = "冰蝎"

		// 该部分参考5.3 核心行为的定义
		// 为了兼容老的规则
		threattype="Webshell"

		// 为了兼容老的规则
		// <分类名称>[核心行为]/<环境前缀>.<家族名称/软件名称>.<家族变种号/软件版本/唯一标识符>
		threatname="HackTool[Webshell]/JSP.Behinder.v3_0_Beta_11_JSPWebshell"

	strings:
		$exec = "extends ClassLoader" wide ascii
		$class = "defineClass" fullword wide ascii
	
		//strings from private rule capa_jsp_safe
		$cjsp_short1 = "<%" ascii wide
		$cjsp_short2 = "%>" wide ascii
		$cjsp_long1 = "<jsp:" ascii wide
		$cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
		// JSF
		$cjsp_long3 = "/jstl/core" ascii wide
		$cjsp_long4 = "<%@p" nocase ascii wide
		$cjsp_long5 = "<%@ " nocase ascii wide
		$cjsp_long6 = "<% " ascii wide
		$cjsp_long7 = "< %" ascii wide
	
		//strings from private rule capa_jsp_input
		// request.getParameter
		$input1 = "getParameter" fullword ascii wide
		// request.getHeaders
		$input2 = "getHeaders" fullword ascii wide
		$input3 = "getInputStream" fullword ascii wide
		$input4 = "getReader" fullword ascii wide
		$req1 = "request" fullword ascii wide
		$req2 = "HttpServletRequest" fullword ascii wide
		$req3 = "getRequest" fullword ascii wide
	
	condition:
		filesize < 10KB and ( 
        $cjsp_short1 at 0 or
			any of ( $cjsp_long* ) or
			$cjsp_short2 in ( filesize-100..filesize ) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize ) 
            )
        ) 
		)
		and ( 
			any of ( $input* ) and
			any of ( $req* ) 
		)
		and $exec and $class
}