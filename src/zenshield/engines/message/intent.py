"""Intent Detection module for Zenshield.

Enumerates and detects all 23 scam and operational intents with:
- Multilingual and Tanglish root recognition
- Language-aware bidirectional negation scoping (English verb-initial and Tamil/Tanglish verb-final)
- Strict differentiation between legitimate advisories (e.g. OTP_NOTIFICATION) and malicious harvesting (OTP_REQUEST)
"""

import re

from zenshield.engines.message.models import IntentMatch
from zenshield.privacy.sanitizer import DualViewText

# 23 Enumerated Intents
INTENTS_ENUM = [
    "OTP_NOTIFICATION",
    "OTP_REQUEST",
    "KYC",
    "ACCOUNT_SUSPENSION",
    "LOGIN_VERIFICATION_CTA",
    "CREDENTIAL_REQUEST",
    "PAYMENT_REQUEST",
    "UPI_COLLECT_OR_QR",
    "REFUND",
    "PRIZE_REWARD",
    "LOAN_OFFER",
    "ADVANCE_FEE",
    "COURIER_CUSTOMS",
    "GOVERNMENT_IMPERSONATION",
    "LEGAL_POLICE_THREAT",
    "TAX_REFUND",
    "ELECTRICITY_UTILITY",
    "TELECOM_SIM",
    "BANK_TRANSACTION_ALERT",
    "JOB_OFFER",
    "INVESTMENT_CRYPTO",
    "APK_INSTALL",
    "FAMILY_EMERGENCY",
]

# Negation patterns for English, Tamil script, and Tanglish
NEGATION_ENGLISH_PREFIX = re.compile(
    r"\b(?:do\s*not|don'?t|never|should\s*not|must\s*not)\s+(?:share|disclose|give|tell|forward|reveal|enter)\b",
    re.IGNORECASE,
)
NEGATION_TAMIL_SUFFIX = re.compile(
    r"(?:பகிர\s*வேண்டாம்|பகிராதீர்கள்|கூறாதீர்கள்|சொல்லாதீர்கள்|கொடுக்காதீர்கள்)",
    re.IGNORECASE,
)
NEGATION_TANGLISH_SUFFIX = re.compile(
    r"\b(?:share\s*pan[a-z]*d[ei]nga|sol[a-z]*d[ei]nga|kuduk[a-z]*d[ei]nga|sollaatheenga|kudukkaatheenga)\b",
    re.IGNORECASE,
)

# OTP Sharing / Request Patterns
OTP_REQUEST_PATTERNS = re.compile(
    r"""(?xi)
    \b(?:
        (?:share|send|forward|enter|submit|provide|give|tell)\s+(?:the\s+)?(?:otp|code|password)|
        (?:otp|code)\s+(?:share|anuppunga|kudunga|solunga|kuduthu|forward)|
        (?:share|kudunga)\s+(?:your\s+)?otp
    )\b|
    (?:otp\s*(?:கொடுத்து|பகிரவும்|அனுப்பவும்))
    """
)

# Intent matchers (on fold view)
INTENT_RULES = {
    "KYC": [
        r"\bkyc\b",
        r"\b(?:kyc\s*(?:update|expire|expir|verification|complete|pending|verify|panunga|சரிபார்ப்பு))\b",
        r"\b(?:update|complete|verify|submit)\s*(?:your\s*)?kyc\b",
        r"\bkyc\s*சரிபார்க்கவும்\b",
    ],
    "ACCOUNT_SUSPENSION": [
        r"\b(?:account|sim|card|services?)\s*(?:will\s*be\s*|is\s*)?(?:blocked|suspended|deactivated|terminated|closed|hold|block\s*aagum|mudakkapadum)\b",
        r"\b(?:account\s*block|block\s*account)\b",
        r"\b(?:block\s*(?:aagum|aagidum|mudakkapadum))\b",
        r"block\s*(?:ஆகும்|ஆகிவிடும்)",
        r"(?:கணக்கு\s*முடக்கப்படும்|முடக்கப்படும்)",
    ],
    "LOGIN_VERIFICATION_CTA": [
        r"\b(?:verify\s*(?:now|immediately|your\s*account|here)|login\s*(?:here|now|to\s*verify)|sign\s*in\s*to\s*confirm)\b",
        r"\b(?:tap\s*(?:below|here|to\s*(?:see|view|pay|check|track))|click\s*below|see\s*(?:the\s*)?full\s*record|view\s*full\s*record)\b",
        r"\b(?:ippove\s*verify|udane\s*verify|சரிபார்க்கவும்)\b",
    ],
    "CREDENTIAL_REQUEST": [
        r"\b(?:password|cvv|pin|atm\s*pin|upi\s*pin|card\s*number|netbanking\s*credentials?)\b",
        r"\b(?:enter|share|verify)\s*(?:your\s*)?(?:mpin|upi\s*pin|cvv|password)\b",
    ],
    "PAYMENT_REQUEST": [
        r"\bpay\s*(?:[₹$]|rs\.?\s*)?[0-9,]+",
        r"\b(?:pay\s*(?:now|immediately|fine|charges?|fee|processing\s*fee|challan|penalty|bill|per\s*challan)|send\s*money|transfer\s*(?:funds|money|amount)|make\s*payment|deposit\s*amount)\b",
        r"\b(?:(?:amount\s*)?awaiting\s*payment|pending\s*(?:payment|challans?|amount|dues|fine|bill)|amount\s*(?:due|pending|payable)|outstanding\s*(?:amount|payment|dues|fine|challan|record)|payment\s*(?:due|pending|awaiting))\b",
        r"\b(?:panam\s*(?:kattunga|anuppunga)|kasu\s*kattunga)\b",
    ],
    "UPI_COLLECT_OR_QR": [
        r"\b(?:upi\s*collect|approve\s*collect|scan\s*qr|scan\s*to\s*receive|accept\s*request)\b",
    ],
    "REFUND": [
        r"\b(?:refund\s*(?:is\s*)?(?:pending|approved|initiated|varum|kedaikum|credited)|claim\s*(?:your\s*)?refund)\b",
    ],
    "PRIZE_REWARD": [
        r"\b(?:won|winner|lucky\s*draw|lottery|prize|reward|gift\s*card|cashback|kbc)\b",
        r"\b(?:receive|get)\s*(?:₹|rs\.?|\$)\s*[0-9,]+\b",
        r"\b(?:use\s*code\s+[a-z0-9_-]+|flat\s*(?:[₹$]|rs\.?)?\s*[0-9,]+\s*off|discount\s*(?:on|per)\s*(?:challan|fine|penalty)|(?:get|avail)\s*discount)\b",
        r"\b(?:parisu\s*(?:vendraar|kedaikum)|inba\s*parisu)\b",
    ],
    "LOAN_OFFER": [
        r"\b(?:pre-?approved\s*loan|instant\s*loan|loan\s*approved|sanctioned\s*amount|kadan\s*(?:kedaikum|varum))\b",
    ],
    "ADVANCE_FEE": [
        r"\b(?:processing\s*fee|registration\s*fee|clearance\s*(?:fee|charge)|advance\s*fee|security\s*deposit)\b",
    ],
    "COURIER_CUSTOMS": [
        r"\b(?:customs\s*(?:clearance|held|duty|seized)|parcel\s*(?:is\s*)?(?:held|pending|failed|undelivered)|held\s*by\s*customs|customs\s*held|dhl|fedex|india\s*post)\b",
    ],
    "GOVERNMENT_IMPERSONATION": [
        r"\b(?:police|cyber\s*crime|rbi|income\s*tax\s*dept|cbi|ed\s*office|court\s*summons?|traffic\s*police|parivahan|mparivahan|rto|e-?challan|traffic\s*(?:department|record))\b",
        r"\b(?:rto\s*fine|challan\s*vanthurukku|traffic\s*fine)\b",
        r"(?:காவல்துறை|வருமான\s*வரி|சைபர்\s*கிரைம்|போக்குவரத்து\s*காவல்)",
    ],
    "LEGAL_POLICE_THREAT": [
        r"\b(?:arrest\s*warrant|fir|police\s*action|legal\s*action|court\s*notice|prosecution|penalty\s*or\s*jail)\b",
        r"\b(?:challan(?:\s*found|\s*pending|\s*notice|\s*issued|\s*record)?|traffic\s*(?:record|violation|challan|offence|penalty|fine)|e-?challan|outstanding\s*(?:traffic\s*)?record|pending\s*challans?|offence:\s*|violation:\s*)\b",
    ],
    "TAX_REFUND": [
        r"\b(?:income\s*tax\s*refund|it\s*department\s*refund|itr\s*refund)\b",
    ],
    "ELECTRICITY_UTILITY": [
        r"\b(?:electricity\s*(?:bill|power|connection)|power\s*will\s*be\s*disconnected|eb\s*bill|மின்சார\s*கட்டணம்)\b",
    ],
    "TELECOM_SIM": [
        r"\b(?:sim\s*(?:block|verification|kyc|expired)|esim\s*(?:update|block)|airtel|jio|vi|bsnl)\b",
    ],
    "BANK_TRANSACTION_ALERT": [
        r"\b(?:debited\s*by|credited\s*to|txn\s*successful|available\s*balance|spent\s*on\s*your\s*card)\b",
    ],
    "JOB_OFFER": [
        r"\b(?:part-?time\s*job|work\s*from\s*home|daily\s*income|youtube\s*like\s*job|telegram\s*task|earn\s*(?:daily|per\s*day))\b",
    ],
    "INVESTMENT_CRYPTO": [
        r"\b(?:crypto\s*(?:trading|investment)|guaranteed\s*returns?|forex\s*trading|double\s*your\s*money|bitcoin|usdt)\b",
    ],
    "APK_INSTALL": [
        r"\b(?:install\s*(?:app|apk)|download\s*(?:this\s*)?apk|sideload|open\s*apk|update\s*app\s*link)\b",
    ],
    "FAMILY_EMERGENCY": [
        r"\b(?:hospitalized|emergency\s*treatment|urgent\s*bail|accident\s*help|need\s*urgent\s*help|save\s*my\s*life)\b",
    ],
}


class IntentDetector:
    """Detects fraud and informational intents with bidirectional negation awareness."""

    def detect(self, dual_view: DualViewText, language: str) -> list[IntentMatch]:
        """Detect matched intents on the fold text."""
        fold_text = dual_view.fold_text
        detected: list[IntentMatch] = []
        matched_intent_names = set()

        # 1. Specialized OTP Intent Evaluation (Notification vs Request)
        otp_matches = self._evaluate_otp_intents(fold_text)
        for m in otp_matches:
            detected.append(m)
            matched_intent_names.add(m.intent)

        # 2. Match remaining 21 intents
        for intent_name, patterns in INTENT_RULES.items():
            if intent_name in matched_intent_names:
                continue

            for pattern in patterns:
                match = re.search(pattern, fold_text, re.IGNORECASE)
                if match:
                    detected.append(
                        IntentMatch(
                            intent=intent_name,
                            confidence=0.92,
                            evidence=f"RULE_INTENT_{intent_name}",
                            matched_terms=[match.group(0).strip()],
                        )
                    )
                    matched_intent_names.add(intent_name)
                    break

        return detected

    def _evaluate_otp_intents(self, fold_text: str) -> list[IntentMatch]:
        """Distinguish between OTP_NOTIFICATION and OTP_REQUEST using bidirectional negation."""
        results: list[IntentMatch] = []
        has_otp_keyword = bool(re.search(r"\b(?:otp|one\s*time\s*password|verification\s*code|ஓடிபி)\b", fold_text))

        if not has_otp_keyword:
            return results

        # Check for explicit OTP sharing request
        has_otp_request = bool(OTP_REQUEST_PATTERNS.search(fold_text))

        # Check for negation in proximity of OTP or sharing terms
        # Split into clauses by punctuation (. , ! ; ?)
        clauses = re.split(r"[.!;?]+", fold_text)
        is_negated_in_clause = False

        for clause in clauses:
            clause = clause.strip()
            if not clause:
                continue
            # If clause mentions OTP
            if re.search(r"\b(?:otp|code|ஓடிபி)\b", clause):
                # Check English prefix negation
                if NEGATION_ENGLISH_PREFIX.search(clause):
                    is_negated_in_clause = True
                    break
                # Check Tamil script suffix negation
                if NEGATION_TAMIL_SUFFIX.search(clause):
                    is_negated_in_clause = True
                    break
                # Check Tanglish suffix negation
                if NEGATION_TANGLISH_SUFFIX.search(clause):
                    is_negated_in_clause = True
                    break

        # Check for callback phishing (e.g. Call ... immediately to verify)
        has_callback_phishing = bool(
            re.search(r"\b(?:call|dial|contact|click|open)\b.*(?:verify|kyc|unblock|complete|confirm)", fold_text)
        )

        if (has_otp_request or has_callback_phishing) and not is_negated_in_clause:
            results.append(
                IntentMatch(
                    intent="OTP_REQUEST",
                    confidence=0.96,
                    evidence="RULE_INTENT_OTP_REQUEST",
                    matched_terms=["otp_request"],
                )
            )
        else:
            # If negated or simply delivering OTP without extraction request
            results.append(
                IntentMatch(
                    intent="OTP_NOTIFICATION",
                    confidence=0.95,
                    evidence="RULE_INTENT_OTP_NOTIFICATION",
                    matched_terms=["otp_notification"],
                )
            )

        return results
