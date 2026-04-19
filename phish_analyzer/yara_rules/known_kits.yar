rule PhishKit_16Shop_Indicators
{
    meta:
        description = "Indicators associated with 16Shop phishing kit family"
        author      = "phish-analyzer"
        severity    = "high"
        attack_ids  = "T1566.001,T1566.002"
        category    = "phishing_kit"
        kit_name    = "16Shop"

    strings:
        $a = "16shop"              nocase
        $b = "/16shop/"            nocase
        $c = "riddlemethis"        nocase
        $d = "antibotlinks"        nocase

    condition:
        any of them
}

rule PhishKit_Generic_PHPMailer_Footprint
{
    meta:
        description = "Generic PHPMailer signature often present in kit-generated phishing"
        author      = "phish-analyzer"
        severity    = "low"
        attack_ids  = "T1566"
        category    = "phishing_kit"

    strings:
        $phpmailer = "X-Mailer: PHPMailer" nocase
        $version   = /PHPMailer\s+[0-9]\.[0-9]/ nocase

    condition:
        $phpmailer or $version
}