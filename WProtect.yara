rule WProtect
{
    strings:
        $hex_0 = { FF 34 85 ?? ?? ?? ?? C3 }

    condition:
        $hex_0
}
