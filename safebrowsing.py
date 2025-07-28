import os
import requests
import logging
import json
import re
import tldextract

# Configure logging
logger = logging.getLogger(__name__)

# Get API key from environment variables or use hardcoded key if not available
API_KEY = os.environ.get("GOOGLE_SAFEBROWSING_API_KEY", "AIzaSyAwxuhys0PJ8FYrjRMzU2QJkJZ44I_GMl0")
SAFE_BROWSING_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

# List of common safe domains
SAFE_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
    "twitter.com", "instagram.com", "linkedin.com", "microsoft.com", "apple.com",
    "github.com", "stackoverflow.com", "netflix.com", "cnn.com", "bbc.com",
    "nytimes.com", "yahoo.com", "mozilla.org", "adobe.com", "nasa.gov",
    "ibm.com", "oracle.com", "salesforce.com", "replit.com"
]

# Regular expressions for basic URL analysis
SUSPICIOUS_PATTERNS = [
    r'(.+?)\.(.+?)\.\1',  # Repeated domain parts (e.g., google.google.com)
    r'([a-zA-Z]+)\1{3,}',  # Repeated characters (e.g., googgggle.com)
    r'bit\.ly|goo\.gl|t\.co|tinyurl|is\.gd',  # URL shorteners (can hide malicious URLs)
    r'free.*download|free.*iphone|free.*money|win.*prize',  # Suspicious marketing terms
    r'bank.*verify|account.*verify|verify.*account|verify.*bank',  # Phishing-related terms
    r'password.*reset|login.*required|signin.*required',  # Authentication-related terms
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # Raw IP addresses (often suspicious)
]

def is_obviously_safe(url):
    """
    Simple heuristic check for obviously safe domains
    """
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    return domain.lower() in SAFE_DOMAINS

def contains_suspicious_patterns(url):
    """
    Check if URL contains any suspicious patterns
    """
    url_lower = url.lower()
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, url_lower):
            return True
    return False

def fallback_check(url):
    """
    Perform a fallback check when API is unavailable
    """
    if is_obviously_safe(url):
        return {
            "status": "likely_safe",
            "message": "This URL appears to be from a known trustworthy domain",
            "details": "API verification unavailable, using domain reputation",
            "recommendation": "This domain is generally considered safe, but proceed with caution."
        }
    elif contains_suspicious_patterns(url):
        return {
            "status": "caution",
            "message": "This URL contains potentially suspicious patterns",
            "details": "API verification unavailable, using pattern analysis",
            "recommendation": "Exercise caution when visiting this link."
        }
    else:
        return {
            "status": "unknown",
            "message": "Unable to verify this URL's safety status",
            "details": "Google Safe Browsing API is currently unavailable",
            "recommendation": "Proceed with caution and verify the source before clicking."
        }

def check_url_safety(url):
    """
    Check if a URL is safe using Google Safe Browsing API.
    Falls back to basic analysis if API is unavailable.
    
    Args:
        url (str): The URL to check
        
    Returns:
        dict: Result with status (safe/unsafe/unknown) and details
    """
    logger.debug(f"Checking URL safety: {url}")
    
    # If no API key is available, use fallback method
    if not API_KEY:
        logger.warning("No Google Safe Browsing API key available, using fallback method")
        return fallback_check(url)
    
    # Prepare the request payload
    request_body = {
        "client": {
            "clientId": "url-safety-checker",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE", 
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    try:
        # Make request to Google Safe Browsing API
        response = requests.post(SAFE_BROWSING_URL, json=request_body)
        response.raise_for_status()
        result = response.json()
        
        # Parse the response
        if "matches" in result and len(result["matches"]) > 0:
            # URL is unsafe - found in threat lists
            threats = []
            for match in result["matches"]:
                threats.append(match.get("threatType", "UNKNOWN_THREAT"))
            
            threat_types = ", ".join(set(threats))
            
            return {
                "status": "unsafe",
                "message": f"This URL was flagged as potentially dangerous",
                "details": f"Detected threat types: {threat_types}",
                "recommendation": "We recommend avoiding this link."
            }
        else:
            # URL is safe - not found in threat lists
            return {
                "status": "safe",
                "message": "This URL appears to be safe",
                "details": "No threats detected",
                "recommendation": "This link appears safe as of now."
            }
    
    except requests.exceptions.RequestException as e:
        logger.error(f"API request error: {str(e)}")
        # Fall back to basic analysis when API is unavailable
        logger.info("Falling back to basic URL analysis")
        return fallback_check(url)
    
    except json.JSONDecodeError:
        logger.error("Error parsing API response")
        return fallback_check(url)
        
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return fallback_check(url)
