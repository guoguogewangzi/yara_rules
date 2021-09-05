
rule everything
{
    meta:
        description = "my first yara rule"
        rev = 1
        author = "zx"
    strings:
        $s1 = "www.voidtools.com/everything"
    condition:
        all of them
}