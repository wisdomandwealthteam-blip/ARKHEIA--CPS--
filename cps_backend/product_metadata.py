"""Public product identity; internal CPS and clearance imports remain unchanged."""
from __future__ import annotations

PRODUCT_TITLE = "ARKHEIA 7™ — Deterministic Agent Gate"
PRODUCT_BRAND = "7™"
PRODUCT_VERSION = "1.0.1"
PRODUCT_PUBLISHER = "ARKHEIA GROUP"
PRODUCT_WEBSITE = "https://ericscott.ai"
PRODUCT_LICENSE = "Proprietary"


def commercial_metadata() -> dict[str, str]:
    """Return a fresh OpenAPI info extension using only declared product facts."""
    return {
        "product": PRODUCT_TITLE,
        "brand": PRODUCT_BRAND,
        "version": PRODUCT_VERSION,
        "publisher": PRODUCT_PUBLISHER,
        "website": PRODUCT_WEBSITE,
        "license": PRODUCT_LICENSE,
    }
