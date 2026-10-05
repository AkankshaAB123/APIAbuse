"""Services subpackage for api_detection."""
from .phishing_url_classifier import PhishingURLClassifierService, get_phishing_url_classifier

__all__ = ["PhishingURLClassifierService", "get_phishing_url_classifier"]
