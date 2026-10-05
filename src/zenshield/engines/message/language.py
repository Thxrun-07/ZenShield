"""Multilingual and Tanglish language detection module for Zenshield.

Performs script ratio analysis (Tamil Unicode vs Latin) and algorithmic
Tanglish canonicalization (repeated letter collapsing, digraph mapping,
terminal vowel pruning, and multi-word n-gram matching).
"""

import re

from zenshield.engines.message.models import LanguageResult

# Canonical Tanglish scam and transactional lexicon (stored in canonicalized form)
CANONICAL_TANGLISH_LEXICON: set[str] = {
    # Verbs / Actions
    "panunga",
    "seiyavum",
    "seinga",
    "seiyunga",
    "kudunga",
    "anuppunga",
    "kuduthu",
    "anuppi",
    "solunga",
    "kelunga",
    "pudunga",
    # Urgency & Time
    "ipove",
    "udane",
    "odane",
    "sekiram",
    "sikiram",
    "vegama",
    "indru",
    "nalaiku",
    # Pronouns & Possessives
    "unga",
    "ungal",
    "ungoda",
    "enakku",
    "namakku",
    # States / Consequences
    "aagum",
    "aagidum",
    "mudakkapadum",
    "nikkappadum",
    "varum",
    "kedaikum",
    "kidaikkum",
    "mudiyum",
    "pogum",
    "illai",
    "theriyum",
    # Negations
    "soladenga",
    "solathenga",
    "kudukadenga",
    "kudukathenga",
    "pagiradenga",
    # Common Nouns / Financial / Tech terms in Tanglish context
    "panam",
    "kasu",
    "kadan",
    "parisu",
    "velai",
    "kattanam",
    "kanakku",
    "seithi",
    "kuriyeedu",
    # Common code-mixed collocations
    "call panunga",
    "click panunga",
    "verify panunga",
    "update panunga",
    "block aagum",
    "cut aagum",
    "refund varum",
    "loan kedaikum",
    "loan kidaikkum",
    "otp kudunga",
    "otp share panunga",
    "kyc panunga",
    "ippove verify",
    "udane verify",
    "account block",
    "close aagum",
}


def canonicalize_tanglish_token(token: str) -> str:
    """Algorithmically normalize a Tanglish token.

    Steps:
    1. Lowercase and trim.
    2. Collapse repeated adjacent consonants and vowels (e.g. pannunga -> panunga).
    3. Map phonetically equivalent digraphs (dh->d, th->t, ee->i, oo->u, aa->a, zh->l).
    4. Strip terminal vowel noise (e.g. panungalen -> panunga).
    """
    if not token:
        return ""

    t = token.lower().strip()
    if not t.isalnum():
        t = re.sub(r"[^\w]", "", t)

    # 1. Digraph and phonetic normalization (must run before single repeat collapse)
    t = t.replace("dh", "d")
    t = t.replace("th", "t")
    t = t.replace("ee", "i")
    t = t.replace("oo", "u")
    t = t.replace("aa", "a")
    t = t.replace("zh", "l")

    # 2. Collapse remaining repeating characters: 2+ repeats -> 1 (e.g. nn -> n, pp -> p)
    t = re.sub(r"(.)\1+", r"\1", t)

    # 3. Terminal suffix noise reduction (e.g. -len, -da, -nga variations)
    t = re.sub(r"len$", "", t)

    return t


class LanguageDetector:
    """Detects message language across English, Tamil Unicode, Tanglish, and Mixed scripts."""

    def __init__(self, custom_tanglish_terms: set[str] | None = None):
        self.tanglish_lexicon = set(CANONICAL_TANGLISH_LEXICON)
        if custom_tanglish_terms:
            for term in custom_tanglish_terms:
                self.tanglish_lexicon.add(canonicalize_tanglish_token(term))

    def detect(self, text: str) -> LanguageResult:
        """Analyze text and determine language, script, confidence, and mixed status."""
        if not text or not text.strip():
            return LanguageResult(
                language="Unknown",
                confidence=0.0,
                script="Unknown",
                is_mixed=False,
                indicators=[],
            )

        tamil_count = 0
        latin_count = 0
        total_letters = 0

        for ch in text:
            code = ord(ch)
            if 0x0B80 <= code <= 0x0BFF:
                tamil_count += 1
                total_letters += 1
            elif ("a" <= ch <= "z") or ("A" <= ch <= "Z"):
                latin_count += 1
                total_letters += 1

        if total_letters == 0:
            return LanguageResult(
                language="Unknown",
                confidence=0.5,
                script="Unknown",
                is_mixed=False,
                indicators=[],
            )

        tamil_ratio = tamil_count / total_letters
        latin_ratio = latin_count / total_letters

        # Predominantly Tamil Unicode (allowing short acronyms like OTP, KYC without falsely labeling as Mixed)
        if tamil_ratio >= 0.70:
            return LanguageResult(
                language="Tamil",
                confidence=min(1.0, 0.85 + tamil_ratio * 0.15),
                script="Tamil",
                is_mixed=latin_ratio >= 0.15,
                indicators=["tamil_unicode_script"],
            )

        # Check for Mixed Script (substantial co-occurrence of both scripts)
        if tamil_ratio >= 0.20 and latin_ratio >= 0.25:
            return LanguageResult(
                language="Mixed",
                confidence=0.90,
                script="Mixed",
                is_mixed=True,
                indicators=["tamil_unicode_detected", "latin_script_detected"],
            )

        if tamil_ratio >= 0.50:
            return LanguageResult(
                language="Tamil",
                confidence=0.85,
                script="Tamil",
                is_mixed=latin_ratio >= 0.10,
                indicators=["tamil_unicode_script"],
            )

        # Predominantly Latin Script: Analyze for Tanglish vs English
        matched_indicators, tanglish_hit_count, density = self._analyze_tanglish(text)

        # Tanglish decision threshold: >=2 distinct lexicon hits or >= 15% density
        if tanglish_hit_count >= 2 or density >= 0.15:
            conf = min(0.98, 0.70 + (tanglish_hit_count * 0.05) + (density * 0.2))
            return LanguageResult(
                language="Tanglish",
                confidence=conf,
                script="Latin",
                is_mixed=False,
                indicators=matched_indicators,
            )

        # Default Latin is English
        return LanguageResult(
            language="English",
            confidence=0.95,
            script="Latin",
            is_mixed=False,
            indicators=["english_vocabulary"],
        )

    def _analyze_tanglish(self, text: str) -> tuple[list[str], int, float]:
        """Tokenize, canonicalize, and extract 1-gram, 2-gram, and 3-gram matches."""
        raw_words = re.findall(r"\b[a-zA-Z]+\b", text.lower())
        if not raw_words:
            return [], 0, 0.0

        canon_tokens = [canonicalize_tanglish_token(w) for w in raw_words]
        matched_indicators: list[str] = []
        hits: set[str] = set()

        # 1-grams
        for tok in canon_tokens:
            if tok in self.tanglish_lexicon:
                hits.add(tok)

        # 2-grams
        for i in range(len(canon_tokens) - 1):
            bigram = f"{canon_tokens[i]} {canon_tokens[i + 1]}"
            if bigram in self.tanglish_lexicon:
                hits.add(bigram)

        # 3-grams
        for i in range(len(canon_tokens) - 2):
            trigram = f"{canon_tokens[i]} {canon_tokens[i + 1]} {canon_tokens[i + 2]}"
            if trigram in self.tanglish_lexicon:
                hits.add(trigram)

        for h in sorted(hits):
            matched_indicators.append(f"tanglish_token:{h}")

        density = len(hits) / max(1, len(raw_words))
        return matched_indicators, len(hits), density
