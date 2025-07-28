import os
import json
import re
import logging
import requests
from datetime import datetime
import string
from models import db, AdVerification
from sqlalchemy import desc

# Configure logging
logger = logging.getLogger(__name__)

def simple_tokenize(text):
    """
    Simple tokenizer function that splits text on whitespace and punctuation
    """
    # Convert to lowercase
    text = text.lower()
    # Replace punctuation with spaces
    for punct in string.punctuation:
        text = text.replace(punct, ' ')
    # Split on whitespace and filter out empty strings
    return [token for token in text.split() if token]

def normalize_text(text):
    """
    Normalize ad content by converting to lowercase and removing special characters
    following the specific steps in the ad verification flow document
    
    Args:
        text (str): The text to normalize
        
    Returns:
        str: Normalized text
    """
    logger.info(f"Normalizing ad text: '{text[:50]}...'")
    
    # Step 1: Normalize Ad Input (exactly as in the document)
    # Convert to lowercase
    normalized = text.lower()
    
    # Remove special characters (including emojis)
    normalized = re.sub(r'[^\w\s]', '', normalized)
    
    # Strip whitespace and remove extra spaces
    normalized = re.sub(r'\s+', ' ', normalized).strip()
    
    logger.info(f"Normalization result: '{text[:50]}...' → '{normalized[:50]}...'")
    
    # Example from document:
    # Original: "🔥 Hurry! Get Free iPhones from Apple! "
    # Normalized: "hurry get free iphones from apple"
    
    return normalized

def extract_keywords(text):
    """
    Extract important keywords from ad text by removing stopwords
    
    Args:
        text (str): The text to extract keywords from
        
    Returns:
        list: List of important keywords
    """
    # Simple stopwords list (common words that don't carry much meaning)
    stopwords = {
        'a', 'an', 'the', 'and', 'or', 'but', 'if', 'because', 'as', 'what',
        'which', 'this', 'that', 'these', 'those', 'then', 'just', 'so', 'than',
        'such', 'both', 'through', 'about', 'for', 'is', 'of', 'while', 'during',
        'to', 'from', 'in', 'out', 'on', 'off', 'over', 'under', 'again', 'further',
        'then', 'once', 'here', 'there', 'when', 'where', 'why', 'how', 'all', 'any',
        'both', 'each', 'few', 'more', 'most', 'other', 'some', 'such', 'no', 'nor',
        'not', 'only', 'own', 'same', 'so', 'than', 'too', 'very', 'can', 'will',
        'just', 'should', 'now', 'at', 'by', 'with', 'be', 'am', 'are', 'was', 'were',
        'has', 'have', 'had', 'do', 'does', 'did', 'up', 'down', 'into', 'get', 'got'
    }
    
    # Tokenize the text
    tokens = simple_tokenize(text)
    
    # Filter out stopwords and very short words
    keywords = [word for word in tokens if word not in stopwords and len(word) > 2]
    
    return keywords

def extract_company(text):
    """
    Attempt to extract company name from ad text
    
    Args:
        text (str): The ad text
        
    Returns:
        str or None: Extracted company name or None if not found
    """
    # Common company indicators in ads
    company_indicators = [
        r'by ([A-Z][A-Za-z0-9\s]{2,})',
        r'from ([A-Z][A-Za-z0-9\s]{2,})',
        r'([A-Z][A-Za-z0-9\s]{2,}) offers',
        r'([A-Z][A-Za-z0-9\s]{2,}) presents',
        r'([A-Z][A-Za-z0-9\s]{2,}) introduces',
        r'brought to you by ([A-Z][A-Za-z0-9\s]{2,})',
        r'exclusively from ([A-Z][A-Za-z0-9\s]{2,})',
        r'proudly by ([A-Z][A-Za-z0-9\s]{2,})',
        r'new from ([A-Z][A-Za-z0-9\s]{2,})',
        r'at ([A-Z][A-Za-z0-9\s]{2,})',
    ]
    
    for pattern in company_indicators:
        matches = re.search(pattern, text)
        if matches:
            company = matches.group(1).strip()
            # Remove common suffix terms
            for suffix in [' Inc', ' LLC', ' Ltd', ' Corporation', ' Company', ' Co', ' Group']:
                if company.endswith(suffix):
                    company = company[:-len(suffix)]
            return company.strip()
    
    return None

def keyword_similarity(keywords1, keywords2):
    """
    Calculate similarity between two sets of keywords
    
    Args:
        keywords1 (list): First list of keywords
        keywords2 (list): Second list of keywords
        
    Returns:
        float: Similarity score (0-1)
    """
    # Convert lists to sets for intersection and union operations
    set1 = set(keywords1)
    set2 = set(keywords2)
    
    # Calculate various similarity metrics as specified in the document
    
    # 1. Jaccard similarity (intersection / union)
    intersection = len(set1.intersection(set2))
    union = len(set1.union(set2))
    jaccard = intersection / union if union > 0 else 0
    
    # 2. Calculate containment (how much of set1 is in set2)
    containment = intersection / len(set1) if len(set1) > 0 else 0
    
    # 3. Calculate overlap coefficient (intersection over size of smaller set)
    smallest_size = min(len(set1), len(set2))
    overlap = intersection / smallest_size if smallest_size > 0 else 0
    
    # Log the similarity metrics for debugging
    logger.debug(f"Keyword similarity - Keywords1: {keywords1[:5]}, Keywords2: {keywords2[:5]}")
    logger.debug(f"Keyword similarity - Jaccard: {jaccard:.2f}, Containment: {containment:.2f}, Overlap: {overlap:.2f}")
    
    # ✅ Smart Match: Use the best of the similarity metrics
    # For the ad verification flow, we're using the max for better matching
    similarity = max(jaccard, containment, overlap)
    
    # We want at least 80% similarity as mentioned in the document
    if similarity >= 0.8:
        logger.debug(f"High similarity match found: {similarity:.2f}")
    
    return similarity

def check_exact_match(normalized_ad):
    """
    Check if the exact normalized ad exists in the database
    
    Args:
        normalized_ad (str): The normalized ad to check
        
    Returns:
        AdVerification or None: Matched verification if found, None otherwise
    """
    # Look for exact match in the database
    exact_match = AdVerification.query.filter_by(normalized_ad=normalized_ad).first()
    
    if exact_match:
        # Update cache hit counter safely
        try:
            exact_match.cached_hit += 1
            db.session.commit()
            logger.info(f"Found exact match for ad in cache, id: {exact_match.id}, cache hits: {exact_match.cached_hit}")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error updating cache hit counter for ad id {exact_match.id}: {str(e)}")
        
    return exact_match

def check_keyword_match(keywords, normalized_ad):
    """
    Check if there is a keyword match in the database
    
    Args:
        keywords (list): The keywords to check against
        normalized_ad (str): Original normalized ad (to avoid returning false matches)
        
    Returns:
        AdVerification or None: Best matched verification if found, None otherwise
    """
    # Get the most recent ads (limit to improve performance)
    recent_ads = AdVerification.query.order_by(desc(AdVerification.verification_date)).limit(100).all()
    
    best_match = None
    # Use 80% threshold as specified in the document
    highest_similarity = 0.8  # Threshold for similarity (80%)
    
    for ad in recent_ads:
        # Skip exact matches to normalized_ad (they would be caught by check_exact_match)
        if ad.normalized_ad == normalized_ad:
            continue
        
        # Get keywords for the stored ad
        stored_keywords = ad.get_keywords()
        
        # Calculate similarity
        similarity = keyword_similarity(keywords, stored_keywords)
        
        # Update best match if we found a better one and it meets the threshold
        if similarity >= highest_similarity:
            highest_similarity = similarity
            best_match = ad
            logger.info(f"Found high similarity match ({similarity:.2f}) with ad ID: {ad.id}")
            # If we find a very high match (>90%), we can stop looking
            if similarity > 0.9:
                break
    
    if best_match:
        # Update cache hit counter safely
        try:
            best_match.cached_hit += 1
            db.session.commit()
            logger.info(f"Found similar ad in cache with similarity {highest_similarity:.2f}, id: {best_match.id}, cache hits: {best_match.cached_hit}")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error updating cache hit counter for ad id {best_match.id}: {str(e)}")
        
    return best_match

def get_mock_ad_response(ad_text):
    """
    Generate a mock response in case the API fails
    
    Args:
        ad_text (str): The ad text to analyze
        
    Returns:
        dict: A mock response in the same format as the API
    """
    return {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "Unable to verify this advertisement due to service unavailability. Please try again later."
                }
            }
        ]
    }

def query_perplexity_api_for_ad(ad_text):
    """
    Query the Perplexity API to verify an advertisement
    
    Args:
        ad_text (str): The advertisement to verify
        
    Returns:
        dict: API response
    """
    # Try to get API key from ConfigManager first, then fallback to environment
    try:
        from config_manager import ConfigManager
        perplexity_api_key = ConfigManager.get_setting('perplexity_api_key', 'api_keys')
    except:
        perplexity_api_key = None
    
    # Fallback to environment variable if not found in config
    if not perplexity_api_key:
        perplexity_api_key = os.environ.get("PERPLEXITY_API_KEY")
    
    if not perplexity_api_key:
        logger.error("Perplexity API key not set in admin config or environment")
        return get_mock_ad_response(ad_text)
    
    headers = {
        "Authorization": f"Bearer {perplexity_api_key}",
        "Content-Type": "application/json"
    }
    
    # Use enhanced system prompt for better analysis
    system_prompt = """You are an expert ad verification assistant. Analyze advertisements for credibility, authenticity, and potential misleading claims. 
Be precise and concise in your analysis. Structure your response in these sections:
1. Analysis: Provide a clear assessment of the advertisement
2. Company Association: Note if the ad appears genuinely connected to any mentioned companies
3. Red Flags: List any suspicious elements (if present)
4. Verdict: Clearly state if the ad is 'trustworthy', 'misleading', or 'uncertain'"""
    
    # Enhanced autoprompt template for Perplexity (Ads)
    user_prompt = f"""Please verify the credibility and trustworthiness of this advertisement:

"{ad_text}"

Analyze whether it is genuinely associated with any mentioned company or contains misleading elements. Consider:
- Unrealistic claims or offers that seem "too good to be true"
- Discrepancies between the ad content and known company practices
- Unusual URLs or contact information
- Urgent or high-pressure tactics
- Poor grammar or unprofessional presentation (for established companies)

Is this a legitimate advertisement or potentially misleading?"""
    
    logger.info(f"Using ad verification prompt: {user_prompt}")
    
    data = {
        "model": "sonar",
        "messages": [
            {
                "role": "system",
                "content": system_prompt
            },
            {
                "role": "user",
                "content": user_prompt
            }
        ],
        "temperature": 0.2,
        "max_tokens": 1024,
        "top_p": 0.9,
        "search_domain_filter": ["perplexity.ai"],
        "return_images": False,
        "return_related_questions": False,
        "search_recency_filter": "month",
        "top_k": 0,
        "stream": False,
        "presence_penalty": 0,
        "frequency_penalty": 1
    }
    
    try:
        response = requests.post(
            "https://api.perplexity.ai/chat/completions",
            headers=headers,
            json=data,
            timeout=30
        )
        
        response.raise_for_status()  # Raise an exception for 4XX/5XX responses
        return response.json()
        
    except Exception as e:
        logger.error(f"Error calling Perplexity API: {str(e)}")
        return get_mock_ad_response(ad_text)

def process_ad_response(response, original_ad, normalized_ad, keywords, mentioned_company=None):
    """
    Process and store the Perplexity API response for an ad
    
    Args:
        response (dict): The API response
        original_ad (str): The original ad text
        normalized_ad (str): The normalized ad text
        keywords (list): The extracted keywords
        mentioned_company (str, optional): Company name mentioned in the ad
        
    Returns:
        AdVerification: The created verification record
    """
    # Extract content from response
    try:
        content = response["choices"][0]["message"]["content"]
    except (KeyError, IndexError):
        content = "Unable to analyze this advertisement due to API response error."
    
    # Determine trustworthiness based on content
    is_trustworthy = None  # Default to uncertain
    
    # Check for indicators of trustworthiness in the content
    if re.search(r'\b(trustworthy|genuine|legitimate|credible|authentic|verified|reliable)\b', content.lower()):
        is_trustworthy = True
    # Check for indicators of misleading content
    elif re.search(r'\b(misleading|suspicious|scam|false|unrealistic|deceptive|fraudulent|dubious)\b', content.lower()):
        is_trustworthy = False
    
    # Create verification record
    verification = AdVerification(
        original_ad=original_ad,
        normalized_ad=normalized_ad,
        keywords="",  # Will be set by set_keywords
        response=content,
        is_trustworthy=is_trustworthy,
        source="perplexity",
        mentioned_company=mentioned_company
    )
    
    # Set keywords
    verification.set_keywords(keywords)
    
    # Save to database
    db.session.add(verification)
    db.session.commit()
    
    return verification

def verify_ad(ad_text):
    """
    Verify an advertisement using smart caching and Perplexity API
    
    Args:
        ad_text (str): The advertisement to verify
        
    Returns:
        dict: Verification result
    """
    try:
        logger.debug(f"Starting verification for ad text: {ad_text[:50]}...")
        
        # Normalize the ad text
        normalized_ad = normalize_text(ad_text)
        logger.debug(f"Normalized ad: {normalized_ad[:50]}...")
        
        # Extract keywords
        keywords = extract_keywords(normalized_ad)
        logger.debug(f"Extracted {len(keywords)} keywords: {', '.join(keywords[:10])}...")
        
        # Try to extract company name
        mentioned_company = extract_company(ad_text)
        logger.debug(f"Extracted company name: {mentioned_company}")
        
        # Check for exact match in cache
        logger.debug("Checking for exact match in cache")
        exact_match = check_exact_match(normalized_ad)
        if exact_match:
            logger.debug(f"Found exact match in cache with ID: {exact_match.id}")
            return {
                'status': 'success',
                'message': 'Advertisement verification retrieved from cache (exact match)',
                'result': exact_match.to_dict(),
                'source': 'cache_exact'
            }
        
        # Check for similar ad in cache
        logger.debug("Checking for similar ad in cache")
        similar_match = check_keyword_match(keywords, normalized_ad)
        if similar_match:
            logger.debug(f"Found similar match in cache with ID: {similar_match.id}")
            return {
                'status': 'success',
                'message': 'Advertisement verification retrieved from cache (similar content)',
                'result': similar_match.to_dict(),
                'source': 'cache_similar'
            }
        
        # No cache hit, query the API
        logger.info("No cache hit for ad, querying Perplexity API")
        api_response = query_perplexity_api_for_ad(ad_text)
        logger.debug("Received response from Perplexity API")
        
        # Process and store API response
        logger.debug("Processing API response")
        verification = process_ad_response(api_response, ad_text, normalized_ad, keywords, mentioned_company)
        logger.debug(f"Created verification record with ID: {verification.id}")
        
        # Format trustworthiness message
        message = ""
        if verification.is_trustworthy is True:
            message = "This advertisement appears to be trustworthy and legitimate."
        elif verification.is_trustworthy is False:
            message = "This advertisement contains potentially misleading or suspicious claims."
        else:
            message = "Unable to definitively determine the trustworthiness of this advertisement."
        
        logger.debug("Returning successful verification result")
        return {
            'status': 'success',
            'message': message,
            'result': verification.to_dict(),
            'source': 'perplexity_api'
        }
    except Exception as e:
        import traceback
        logger.error(f"Error in verify_ad function: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise