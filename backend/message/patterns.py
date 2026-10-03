"""Risk pattern and heuristics matching module for Zenshield.

Evaluates 11 deterministic risk signals:
- malware_risk, credential_request, sensitive_data_request, financial_request,
  suspicious_url, threat, urgency, impersonation, social_engineering,
  call_to_action, prompt_injection_attempt.
Uses precompiled bounded regexes on the fold view, deduplicates spans,
and enforces mutual exclusion between credential_request and sensitive_data_request.
"""

import re

from backend.config import settings
from backend.message.models import IntentMatch, RiskSignal
from backend.privacy.models import DetectedEntity, URLMetadata
from backend.privacy.sanitizer import DualViewText

# Prompt Injection Attack Patterns (Deterministic signal + LLM bypass)
PROMPT_INJECTION_REGEX = re.compile(
    r"""(?xi)
    \b(?:
        ignore\s+(?:all\s+)?previous\s+instructions|
        system\s+override|
        send\s+(?:the\s+)?secret\s+(?:system\s+)?prompt|
        reveal\s+(?:your\s+)?system\s+prompt|
        you\s+are\s+now\s+(?:a|an)|
        disregard\s+(?:all\s+)?rules|
        mark\s+this\s+message\s+as\s+safe
    )\b
    """
)

# Urgency Patterns
URGENCY_REGEX = re.compile(
    r"""(?xi)
    \b(?:
        immediately|urgent(?:ly)?|within\s+\d{1,2}\s+(?:minutes?|hours?)|
        today\s+only|act\s+now|last\s+warning|expir(?:es?|ing)\s+(?:soon|today)|
        ippove|ipove|udane|odane|seekiram|sikiram|vegama|indru
    )\b|
    (?:உடனே|உடனடியாக|இன்றே)
    """
)

# Threat Patterns
THREAT_REGEX = re.compile(
    r"""(?xi)
    \b(?:
        account\s*(?:will\s*be)?\s*(?:suspended|blocked|terminated|closed)|
        service\s*(?:will\s*be)?\s*disconnected|sim\s*(?:will\s*be)?\s*blocked|
        police\s*(?:complaint|action|case)|legal\s*action|arrest\s*warrant|
        penalty|fine|fir|court\s*summons|prosecution|jail|
        block\s*aagum|mudakkapadum|cut\s*aagum
    )\b|
    (?:கணக்கு\s*முடக்கப்படும்|முடக்கப்படும்|தடை\s*செய்யப்படும்)
    """
)

# Malware Risk Patterns
MALWARE_REGEX = re.compile(
    r"""(?xi)
    \b(?:
        install\s*(?:this\s*)?(?:app|apk)|download\s*(?:this\s*)?(?:app|apk)|
        open\s*(?:this\s*)?apk|\.apk\b|sideload\s*(?:app)?|
        update\s*banking\s*app\s*link
    )\b
    """
)

# Financial Request Patterns
FINANCIAL_REQUEST_REGEX = re.compile(
    r"""(?xi)
    \b(?:
        pay\s*(?:now|fine|fee|charges?|immediately|₹|\$|rs\.?)|
        send\s*(?:money|funds)|processing\s*fee|registration\s*fee|
        advance\s*payment|clearance\s*fee|deposit\s*fee|
        panam\s*(?:kattunga|anuppunga)|kasu\s*kattunga
    )\b
    """
)

# Impersonation Patterns
IMPERSONATION_REGEX = re.compile(
    r"""(?xi)
    \b(?:
        cyber\s*crime(?:\s*department)?|traffic\s*police|police\s*department|
        income\s*tax\s*(?:department|dept|office)|rbi|cbi|ed\s*office|
        sbi\s*bank|hdfc\s*bank|icici\s*bank|customs\s*officer|
        dhl\s*express|fedex\s*courier|india\s*post
    )\b
    """
)

# Social Engineering Patterns
SOCIAL_ENGINEERING_REGEX = re.compile(
    r"""(?xi)
    \b(?:
        won\s*(?:a\s*)?(?:lottery|prize|car|cash|reward)|
        pre-?approved\s*loan|guaranteed\s*(?:returns?|income|profit)|
        work\s*from\s*home\s*daily|part-?time\s*job\s*offer|
        congratulations\s*you\s*won|claim\s*your\s*reward|
        (?:receive|get)\s*(?:₹|rs\.?|\$)\s*[0-9,]+|
        (?:receive|get)\s*[0-9,]+\s*(?:immediately|instantly)
    )\b
    """
)

# Call to Action Patterns (Link, Reply, App)
CTA_LINK_OR_REPLY_REGEX = re.compile(
    r"""(?xi)
    \b(?:
        click\s*(?:here|this\s*link|on\s*the\s*link)|open\s*(?:the\s*)?link|
        visit\s*(?:this\s*url|portal)|reply\s*(?:yes|no|stop|help|with)|
        call\s*(?:now|immediately|us|our\s*executive)|call\s*panunga
    )\b
    """
)


class PatternMatcher:
    """Evaluates multi-vector risk signals against sanitized message content."""

    def match_signals(
        self,
        dual_view: DualViewText,
        intents: list[IntentMatch],
        entities: list[DetectedEntity],
        url_metadata: list[URLMetadata],
    ) -> list[RiskSignal]:
        """Detect risk signals with mutual exclusion and safe non-PII evidence."""
        signals: list[RiskSignal] = []
        emitted_categories: set[str] = set()
        fold_text = dual_view.fold_text

        intent_set = {m.intent for m in intents}

        # 1. Prompt Injection Attempt (Deterministic high-priority signal)
        if PROMPT_INJECTION_REGEX.search(fold_text):
            signals.append(
                RiskSignal(
                    name="Prompt injection attempt",
                    category="prompt_injection_attempt",
                    severity="high",
                    evidence="Message contains adversarial instructions directed at verification system",
                    weight=settings.WEIGHT_PROMPT_INJECTION_ATTEMPT,
                    confidence=0.98,
                    rule_id="RULE_PROMPT_INJECTION_ATTEMPT",
                )
            )
            emitted_categories.add("prompt_injection_attempt")

        # 2. Malware Risk
        if MALWARE_REGEX.search(fold_text) or "APK_INSTALL" in intent_set:
            signals.append(
                RiskSignal(
                    name="Malware risk",
                    category="malware_risk",
                    severity="critical",
                    evidence="Message instructs user to download or install external application/APK",
                    weight=settings.WEIGHT_MALWARE_RISK,
                    confidence=0.95,
                    rule_id="RULE_MALWARE_APK_INSTALL",
                )
            )
            emitted_categories.add("malware_risk")

        # 3. Credential Request (Mutual exclusion with sensitive_data_request)
        is_cred_req = (
            "OTP_REQUEST" in intent_set or
            "CREDENTIAL_REQUEST" in intent_set or
            bool(re.search(r"\b(?:share|enter|send|kudunga)\s+(?:your\s+)?(?:otp|password|pin|cvv)\b", fold_text)) or
            bool(re.search(r"otp\s*(?:கொடுத்து|பகிரவும்)", fold_text))
        )
        if is_cred_req:
            signals.append(
                RiskSignal(
                    name="Credential request",
                    category="credential_request",
                    severity="critical",
                    evidence="Message solicits confidential credentials (OTP, password, PIN, or CVV)",
                    weight=settings.WEIGHT_CREDENTIAL_REQUEST,
                    confidence=0.98,
                    rule_id="RULE_CREDENTIAL_REQUEST",
                )
            )
            emitted_categories.add("credential_request")

        # 4. Sensitive Data Request (Only if not already fired as credential_request)
        elif bool(re.search(r"\b(?:share|send|verify)\s+(?:your\s+)?(?:aadhaar|pan|bank\s*statement|account\s*details)\b", fold_text)):
            signals.append(
                RiskSignal(
                    name="Sensitive data request",
                    category="sensitive_data_request",
                    severity="high",
                    evidence="Message requests sensitive identity documents or financial statements",
                    weight=settings.WEIGHT_SENSITIVE_DATA_REQUEST,
                    confidence=0.90,
                    rule_id="RULE_SENSITIVE_DATA_REQUEST",
                )
            )
            emitted_categories.add("sensitive_data_request")

        # 5. Financial Request
        if FINANCIAL_REQUEST_REGEX.search(fold_text) or "PAYMENT_REQUEST" in intent_set or "ADVANCE_FEE" in intent_set:
            signals.append(
                RiskSignal(
                    name="Financial request",
                    category="financial_request",
                    severity="high",
                    evidence="Message demands payment, transfer, or advance processing fee",
                    weight=settings.WEIGHT_FINANCIAL_REQUEST,
                    confidence=0.92,
                    rule_id="RULE_FINANCIAL_REQUEST",
                )
            )
            emitted_categories.add("financial_request")

        # 6. Suspicious URL Signal
        if any(u.is_suspicious for u in url_metadata):
            signals.append(
                RiskSignal(
                    name="Suspicious URL",
                    category="suspicious_url",
                    severity="high",
                    evidence="Message includes a suspicious or lookalike link/shortener",
                    weight=settings.WEIGHT_SUSPICIOUS_URL,
                    confidence=0.95,
                    rule_id="RULE_SUSPICIOUS_URL",
                )
            )
            emitted_categories.add("suspicious_url")

        # 7. Threat Signal
        if THREAT_REGEX.search(fold_text) or "ACCOUNT_SUSPENSION" in intent_set or "LEGAL_POLICE_THREAT" in intent_set:
            signals.append(
                RiskSignal(
                    name="Threat",
                    category="threat",
                    severity="medium",
                    evidence="Message contains intimidation, account suspension, or legal enforcement threats",
                    weight=settings.WEIGHT_THREAT,
                    confidence=0.92,
                    rule_id="RULE_THREAT_COERCION",
                )
            )
            emitted_categories.add("threat")

        # 8. Urgency Signal
        if URGENCY_REGEX.search(fold_text):
            signals.append(
                RiskSignal(
                    name="Urgency",
                    category="urgency",
                    severity="medium",
                    evidence="Message exerts time pressure to act immediately",
                    weight=settings.WEIGHT_URGENCY,
                    confidence=0.90,
                    rule_id="RULE_URGENCY_PRESSURE",
                )
            )
            emitted_categories.add("urgency")

        # 9. Impersonation Signal
        if IMPERSONATION_REGEX.search(fold_text) or "GOVERNMENT_IMPERSONATION" in intent_set:
            signals.append(
                RiskSignal(
                    name="Impersonation",
                    category="impersonation",
                    severity="medium",
                    evidence="Message references government authority, law enforcement, or financial institutions",
                    weight=settings.WEIGHT_IMPERSONATION,
                    confidence=0.88,
                    rule_id="RULE_IMPERSONATION",
                )
            )
            emitted_categories.add("impersonation")

        # 10. Social Engineering Signal
        if SOCIAL_ENGINEERING_REGEX.search(fold_text) or "PRIZE_REWARD" in intent_set or "JOB_OFFER" in intent_set or "INVESTMENT_CRYPTO" in intent_set:
            signals.append(
                RiskSignal(
                    name="Social engineering",
                    category="social_engineering",
                    severity="medium",
                    evidence="Message utilizes reward, easy income, or pre-approved offers as lures",
                    weight=settings.WEIGHT_SOCIAL_ENGINEERING,
                    confidence=0.88,
                    rule_id="RULE_SOCIAL_ENGINEERING",
                )
            )
            emitted_categories.add("social_engineering")

        # 11. Call to Action (Differentiating Toll-free vs Standard Phone Call)
        has_cta_text = bool(CTA_LINK_OR_REPLY_REGEX.search(fold_text))
        phone_entities = [e for e in entities if e.entity_type == "PHONE"]
        has_phone = len(phone_entities) > 0

        if has_cta_text or has_phone:
            # Check if all detected phones are toll-free
            is_only_toll_free = has_phone and all(p.metadata.get("is_toll_free") is True for p in phone_entities)
            weight = settings.WEIGHT_CALL_TO_ACTION_TOLL_FREE if is_only_toll_free else settings.WEIGHT_CALL_TO_ACTION
            rule_id = "RULE_CTA_TOLL_FREE" if is_only_toll_free else "RULE_CTA_ACTION"

            signals.append(
                RiskSignal(
                    name="Call to action",
                    category="call_to_action",
                    severity="low" if is_only_toll_free else "medium",
                    evidence="Message directs recipient to call, click, or reply",
                    weight=weight,
                    confidence=0.85,
                    rule_id=rule_id,
                )
            )
            emitted_categories.add("call_to_action")

        return signals
