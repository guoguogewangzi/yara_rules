rule HackTool_Webshell_ASP_Behinder_v3_0_Beta_11_ASP_Runtime_Compile_Webshell
{
	meta:
		// 规则创建时间
		date_created = "2021-09-06"
		// 规则最后一次修改时间
		date_modified = "2021-09-06"
		// 规则最后一次修改人（邮箱）
		author = "zhangxin2@antiy.cn"
		// 规则匹配的样本的MD5
		md5 = "f8de2e99dc7523d2c83d1a48e844c5ff"
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
		threatname="HackTool[Webshell]/ASP.Behinder.v3_0_Beta_11_ASP_Runtime_Compile_Webshell"

	strings:
		$payload_reflection1 = "System.Reflection" nocase wide ascii
		$payload_reflection2 = "Assembly" fullword nocase wide ascii
		$payload_load_reflection1 = /[."']Load\b/ nocase wide ascii
        // only match on "load" or variable which might contain "load"
		$payload_load_reflection2 = /\bGetMethod\(("load|\w)/ nocase wide ascii
		$payload_compile1 = "GenerateInMemory" nocase wide ascii
		$payload_compile2 = "CompileAssemblyFromSource" nocase wide ascii
		$payload_invoke1 = "Invoke" fullword nocase wide ascii
		$payload_invoke2 = "CreateInstance" fullword nocase wide ascii
        $rc_fp1 = "Request.MapPath"
        $rc_fp2 = "<body><mono:MonoSamplesHeader runat=\"server\"/>" wide ascii
	
		//strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
		$asp_input1 = "request" fullword nocase wide ascii
		$asp_input2 = "Page_Load" fullword nocase wide ascii
        // base64 of Request.Form(
		$asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
		$asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
		$asp_xml_method1 = "GET" fullword wide ascii
		$asp_xml_method2 = "POST" fullword wide ascii
		$asp_xml_method3 = "HEAD" fullword wide ascii
        // dynamic form
        $asp_form1 = "<form " wide ascii
        $asp_form2 = "<Form " wide ascii
        $asp_form3 = "<FORM " wide ascii
        $asp_asp   = "<asp:" wide ascii
        $asp_text1 = ".text" wide ascii
        $asp_text2 = ".Text" wide ascii
	
	condition:
		filesize < 10KB and ( 
			any of ( $asp_input* ) or
        (
            $asp_xml_http and
            any of ( $asp_xml_method* )
        ) or
        (
            any of ( $asp_form* ) and
            any of ( $asp_text* ) and
            $asp_asp
        ) 
		)
		and not any of ( $rc_fp* ) and 
		( ( all of ( $payload_reflection* ) and any of ( $payload_load_reflection* ) ) or all of ( $payload_compile* ) ) and any of ( $payload_invoke* )
}
