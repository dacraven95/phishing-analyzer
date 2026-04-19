rule HTML_Obfuscated_JavaScript
{
    meta:
        description = "HTML contains heavily obfuscated JavaScript"
        author      = "phish-analyzer"
        severity    = "high"
        attack_ids  = "T1027,T1059.007"
        category    = "obfuscation"

    strings:
        $eval      = "eval(" nocase
        $fromcode  = "fromCharCode" nocase
        $atob      = "atob(" nocase
        $unescape  = "unescape(" nocase
        $b64blob   = /[A-Za-z0-9+\/]{300,}={0,2}/

    condition:
        2 of ($eval, $fromcode, $atob, $unescape) and $b64blob
}

rule HTML_Hidden_Iframe
{
    meta:
        description = "HTML contains hidden iframe (common redirect technique)"
        author      = "phish-analyzer"
        severity    = "medium"
        attack_ids  = "T1566.001,T1204.001"
        category    = "evasion"

    strings:
        $iframe1 = /<iframe[^>]+style\s*=\s*["'][^"']*display\s*:\s*none/ nocase
        $iframe2 = /<iframe[^>]+(width|height)\s*=\s*["']?(0|1)["']?/ nocase
        $iframe3 = /<iframe[^>]+hidden/ nocase

    condition:
        any of them
}

rule HTML_Meta_Refresh_Redirect
{
    meta:
        description = "HTML uses meta refresh to redirect to external URL"
        author      = "phish-analyzer"
        severity    = "medium"
        attack_ids  = "T1566.002,T1204.001"
        category    = "redirect"

    strings:
        $meta = /<meta\s+http-equiv\s*=\s*["']?refresh["']?[^>]+url\s*=\s*https?:\/\// nocase

    condition:
        $meta
}