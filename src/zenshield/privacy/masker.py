"""Deterministic Masking module for Zenshield.

Replaces detected PII entities right-to-left on canonical text, preventing
offset drift and maintaining deterministic, request-scoped person numbering (PERSON_01).
Collects masked entity counts and URL metadata without retaining original values.
"""

from zenshield.privacy.models import DetectedEntity, MaskedResult, URLMetadata


class Masker:
    """Performs deterministic right-to-left span masking."""

    def mask(
        self,
        canonical_text: str,
        entities: list[DetectedEntity],
    ) -> MaskedResult:
        """Mask all detected entities in canonical text from right to left.

        Assigns consistent placeholders (PERSON_01, PERSON_02) for person names
        within the scope of this single request.
        """
        # Maintain person name to placeholder mapping for this request
        person_name_map: dict[str, str] = {}
        person_counter = 1

        # Pre-assign replacements for PERSON entities
        for entity in entities:
            if entity.entity_type == "PERSON":
                norm_name = entity.original_value.strip().lower()
                if norm_name not in person_name_map:
                    placeholder = f"PERSON_{person_counter:02d}"
                    person_name_map[norm_name] = placeholder
                    person_counter += 1
                entity.replacement = person_name_map[norm_name]
            elif not entity.replacement:
                # Default fallback if not already assigned
                entity.replacement = f"[{entity.entity_type}_REDACTED]"

        # Sort entities right-to-left (descending by start index)
        # to ensure leftward character offsets remain completely stable
        sorted_entities = sorted(entities, key=lambda e: e.start, reverse=True)

        masked_chars = list(canonical_text)
        masked_entity_counts: dict[str, int] = {}
        url_metadata_list: list[URLMetadata] = []

        for entity in sorted_entities:
            replacement = entity.replacement or f"[{entity.entity_type}_REDACTED]"
            # Replace characters from entity.start to entity.end with replacement
            masked_chars[entity.start : entity.end] = list(replacement)

            # Accumulate masked counts
            masked_entity_counts[entity.entity_type] = masked_entity_counts.get(entity.entity_type, 0) + 1

            # Collect URL metadata if entity is URL
            if entity.entity_type == "URL" and entity.metadata:
                try:
                    url_meta = URLMetadata(**entity.metadata)
                    url_metadata_list.append(url_meta)
                except Exception:
                    pass

        masked_text = "".join(masked_chars)

        # Restore URL metadata order matching text appearance (left to right)
        url_metadata_list.reverse()

        return MaskedResult(
            canonical_text=canonical_text,
            masked_text=masked_text,
            entities=entities,
            masked_entity_counts=masked_entity_counts,
            url_metadata=url_metadata_list,
        )
