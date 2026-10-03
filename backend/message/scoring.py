"""Deterministic integer scoring engine for Zenshield.

Computes base weights, non-linear combination bonuses, floor anchors,
and bounds all arithmetic strictly within [0, 100].
"""


from backend.config import settings
from backend.message.models import (
    BonusItem,
    Classification,
    IntentMatch,
    RiskLevel,
    RiskSignal,
    ScoreBreakdown,
)


class ScoringEngine:
    """Computes explainable, reproducible integer risk scores."""

    def compute_score(
        self,
        signals: list[RiskSignal],
        intents: list[IntentMatch],
        llm_delta: int = 0,
    ) -> tuple[ScoreBreakdown, RiskLevel, Classification]:
        """Calculate base score, bonuses, bounds, floor anchors, and classifications."""
        intent_set = {i.intent for i in intents}
        signal_cat_map = {s.category: s for s in signals}

        # 1. Base Score calculation (distinct categories only)
        base_raw = sum(s.weight for s in signal_cat_map.values())
        base_capped = min(settings.BASE_SCORE_CAP, base_raw)

        # 2. Combination Bonuses
        bonuses: list[BonusItem] = []

        # Credential Request + Urgency (+15)
        if "credential_request" in signal_cat_map and "urgency" in signal_cat_map:
            bonuses.append(
                BonusItem(
                    name="credential_urgency",
                    weight=settings.BONUS_CRED_URGENCY,
                    rule_id="BONUS_CRED_URGENCY",
                )
            )

        # Credential Request + Phone CTA (+10)
        # Only applies if phone CTA is standard (not toll-free without request)
        if "credential_request" in signal_cat_map and "call_to_action" in signal_cat_map:
            cta_signal = signal_cat_map["call_to_action"]
            if cta_signal.rule_id != "RULE_CTA_TOLL_FREE":
                bonuses.append(
                    BonusItem(
                        name="credential_phone_cta",
                        weight=settings.BONUS_CRED_PHONE_CTA,
                        rule_id="BONUS_CRED_PHONE_CTA",
                    )
                )

        # KYC / Verification intent + Suspicious URL (+20)
        if ("KYC" in intent_set or "LOGIN_VERIFICATION_CTA" in intent_set) and "suspicious_url" in signal_cat_map:
            bonuses.append(
                BonusItem(
                    name="kyc_suspicious_url",
                    weight=settings.BONUS_KYC_SUSPICIOUS_URL,
                    rule_id="BONUS_KYC_SUSPICIOUS_URL",
                )
            )

        # Government Impersonation + Threat (+20)
        if ("GOVERNMENT_IMPERSONATION" in intent_set or "impersonation" in signal_cat_map) and "threat" in signal_cat_map:
            bonuses.append(
                BonusItem(
                    name="gov_threat",
                    weight=settings.BONUS_GOV_THREAT,
                    rule_id="BONUS_GOV_THREAT",
                )
            )

        # Prize / Reward + Payment Request (+20)
        if "PRIZE_REWARD" in intent_set and "financial_request" in signal_cat_map:
            bonuses.append(
                BonusItem(
                    name="prize_payment",
                    weight=settings.BONUS_PRIZE_PAYMENT,
                    rule_id="BONUS_PRIZE_PAYMENT",
                )
            )

        # Loan Offer + Advance Fee (+20)
        if "LOAN_OFFER" in intent_set and ("ADVANCE_FEE" in intent_set or "financial_request" in signal_cat_map):
            bonuses.append(
                BonusItem(
                    name="loan_advance_fee",
                    weight=settings.BONUS_LOAN_ADVANCE_FEE,
                    rule_id="BONUS_LOAN_ADVANCE_FEE",
                )
            )

        # Courier + Fee (+15)
        if "COURIER_CUSTOMS" in intent_set and "financial_request" in signal_cat_map:
            bonuses.append(
                BonusItem(
                    name="courier_fee",
                    weight=settings.BONUS_COURIER_FEE,
                    rule_id="BONUS_COURIER_FEE",
                )
            )

        # Account Suspension + Login / Verification CTA (+20)
        if "ACCOUNT_SUSPENSION" in intent_set and ("LOGIN_VERIFICATION_CTA" in intent_set or "call_to_action" in signal_cat_map):
            bonuses.append(
                BonusItem(
                    name="suspension_login",
                    weight=settings.BONUS_SUSPENSION_LOGIN,
                    rule_id="BONUS_SUSPENSION_LOGIN",
                )
            )

        # Threat + Urgency + Payment (+15)
        if "threat" in signal_cat_map and "urgency" in signal_cat_map and "financial_request" in signal_cat_map:
            bonuses.append(
                BonusItem(
                    name="threat_urgency_payment",
                    weight=settings.BONUS_THREAT_URGENCY_PAYMENT,
                    rule_id="BONUS_THREAT_URGENCY_PAYMENT",
                )
            )

        bonus_total = sum(b.weight for b in bonuses)
        pre_score = min(100, base_capped + bonus_total)

        # 3. LLM Guard: Clamping delta and prohibiting raising clean messages
        clamped_llm_delta = max(-10, min(10, llm_delta))
        if len(signals) == 0:
            # If no deterministic signals fired, LLM cannot raise score
            clamped_llm_delta = min(0, clamped_llm_delta)

        intermediate_score = max(0, min(100, pre_score + clamped_llm_delta))

        # 4. Safety Floor Anchors
        anchors_applied: list[str] = []
        final_score = intermediate_score

        # Floor 50 if malware_risk, or non-negated credential_request + call_to_action
        has_malware = "malware_risk" in signal_cat_map
        has_cred_cta = "credential_request" in signal_cat_map and "call_to_action" in signal_cat_map

        if (has_malware or has_cred_cta) and final_score < settings.CRITICAL_SAFETY_FLOOR:
            final_score = settings.CRITICAL_SAFETY_FLOOR
            anchor_name = "FLOOR_50_MALWARE" if has_malware else "FLOOR_50_CRED_CTA"
            anchors_applied.append(anchor_name)

        # Final guarantee of [0, 100]
        final_score = max(0, min(100, final_score))

        # 5. Classification and Risk Level Mapping
        risk_level, classification = self._classify(final_score)

        breakdown = ScoreBreakdown(
            base_raw=base_raw,
            base_capped=base_capped,
            bonuses=bonuses,
            llm_delta=clamped_llm_delta,
            anchors_applied=anchors_applied,
            final=final_score,
        )

        return breakdown, risk_level, classification

    def _classify(self, score: int) -> tuple[RiskLevel, Classification]:
        """Map score to RiskLevel and Classification using configured thresholds."""
        if score <= settings.THRESHOLD_LOW:
            return RiskLevel.LOW, Classification.LIKELY_SAFE
        elif score <= settings.THRESHOLD_MEDIUM:
            return RiskLevel.MEDIUM, Classification.SUSPICIOUS
        elif score <= settings.THRESHOLD_HIGH:
            return RiskLevel.HIGH, Classification.POTENTIAL_PHISHING
        else:
            return RiskLevel.CRITICAL, Classification.HIGH_RISK_SCAM
