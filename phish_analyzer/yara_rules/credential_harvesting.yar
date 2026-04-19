rule HTML_Credential_Form_Generic
{
    meta:
        description = "HTML form that captures credentials with suspicious action target"
        author      = "phish-analyzer"
        severity    = "high"
        attack_ids  = "T1566.001,T1598.002"
        category    = "credential_harvesting"

    strings:
        $form     = /<form[^>]+action\s*=\s*["'](https?:\/\/)?[^"']{5,}["'][^>]*>/ nocase
        $password = /<input[^>]+type\s*=\s*["']?password["']?/ nocase
        $username = /<input[^>]+(name|id)\s*=\s*["']?(user|email|login|username)["']?/ nocase

    condition:
        $form and $password and $username
}

rule HTML_Fake_Login_Brand_Impersonation
{
    meta:
        description = "HTML content mimicking well-known brand login page"
        author      = "phish-analyzer"
        severity    = "high"
        attack_ids  = "T1566.001,T1656"
        category    = "brand_impersonation"

    strings:
        $brand1  = /sign\s*in\s*to\s*(your\s*)?(microsoft|office\s*365|outlook)/ nocase
        $brand2  = /sign\s*in\s*to\s*(your\s*)?(apple|icloud)/ nocase
        $brand3  = /sign\s*in\s*to\s*(your\s*)?(google|gmail)/ nocase
        $brand4  = /log\s*in\s*to\s*(your\s*)?(paypal|amazon)/ nocase
        $form    = /<input[^>]+type\s*=\s*["']?password["']?/ nocase

    condition:
        ($brand1 or $brand2 or $brand3 or $brand4) and $form
}

rule HTML_OTP_Harvesting
{
    meta:
        description = "HTML content requesting one-time password or 2FA code"
        author      = "phish-analyzer"
        severity    = "critical"
        attack_ids  = "T1566.002,T1598.003"
        category    = "credential_harvesting"

    strings:
        $otp1 = /verification\s*code/ nocase
        $otp2 = /one[-\s]time\s*(password|code)/ nocase
        $otp3 = /2fa\s*code/ nocase
        $otp4 = /authenticator\s*code/ nocase
        $otp5 = /enter\s*the\s*code/ nocase
        $form = /<input/ nocase

    condition:
        1 of ($otp*) and $form
}