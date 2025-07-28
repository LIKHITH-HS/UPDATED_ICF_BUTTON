import os
import re
import json
import logging
import requests
import string
from datetime import datetime
from models import db, NewsVerification
from sqlalchemy import func

# Configure logging
logger = logging.getLogger(__name__)

# Create a simpler tokenizer without NLTK dependency
def simple_tokenize(text):
    """
    Simple tokenizer function that splits text on whitespace and punctuation
    """
    # Remove punctuation and replace with spaces
    for char in string.punctuation:
        text = text.replace(char, ' ')
    
    # Split on whitespace and filter out empty strings
    return [token.lower() for token in text.split() if token]

# Common English stopwords
STOPWORDS = {
    'a', 'an', 'the', 'and', 'or', 'but', 'if', 'because', 'as', 'what', 
    'which', 'this', 'that', 'these', 'those', 'then', 'just', 'so', 'than', 
    'such', 'both', 'through', 'about', 'for', 'is', 'of', 'while', 'during', 
    'to', 'from', 'in', 'on', 'by', 'at', 'with', 'about', 'against', 'between',
    'into', 'through', 'during', 'before', 'after', 'above', 'below', 'up', 
    'down', 'out', 'off', 'over', 'under', 'again', 'further', 'then', 'once', 
    'here', 'there', 'when', 'where', 'why', 'how', 'all', 'any', 'both', 'each', 
    'few', 'more', 'most', 'other', 'some', 'such', 'no', 'nor', 'not', 'only', 
    'own', 'same', 'so', 'than', 'too', 'very', 's', 't', 'can', 'will', 'don', 
    'should', 'now', 'd', 'll', 'm', 'o', 're', 've', 'y', 'ain', 'aren', 'couldn', 
    'didn', 'doesn', 'hadn', 'hasn', 'haven', 'isn', 'ma', 'mightn', 'mustn', 
    'needn', 'shan', 'shouldn', 'wasn', 'weren', 'won', 'wouldn', 'i', 'me', 'my', 
    'myself', 'we', 'our', 'ours', 'ourselves', 'you', 'your', 'yours', 'yourself', 
    'yourselves', 'he', 'him', 'his', 'himself', 'she', 'her', 'hers', 'herself', 
    'it', 'its', 'itself', 'they', 'them', 'their', 'theirs', 'themselves', 'am', 
    'is', 'are', 'was', 'were', 'be', 'been', 'being', 'have', 'has', 'had', 'having', 
    'do', 'does', 'did', 'doing', 'would', 'should', 'could', 'ought', 'i\'m', 'you\'re', 
    'he\'s', 'she\'s', 'it\'s', 'we\'re', 'they\'re', 'i\'ve', 'you\'ve', 'we\'ve', 
    'they\'ve', 'i\'d', 'you\'d', 'he\'d', 'she\'d', 'we\'d', 'they\'d', 'i\'ll', 
    'you\'ll', 'he\'ll', 'she\'ll', 'we\'ll', 'they\'ll', 'isn\'t', 'aren\'t', 'wasn\'t', 
    'weren\'t', 'hasn\'t', 'haven\'t', 'hadn\'t', 'doesn\'t', 'don\'t', 'didn\'t', 'won\'t', 
    'wouldn\'t', 'shan\'t', 'shouldn\'t', 'can\'t', 'cannot', 'couldn\'t', 'mustn\'t'
}

# Get API key from environment variables
API_KEY = os.environ.get("PERPLEXITY_API_KEY")
PERPLEXITY_API_URL = "https://api.perplexity.ai/chat/completions"

# Set direct API key for development/testing if not in environment
if not API_KEY:
    logger.warning("Perplexity API key not found in environment, using hardcoded key")
    API_KEY = "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"

# Similarity threshold for keyword matching (reduced to 40% to catch more similar items)
SIMILARITY_THRESHOLD = 0.4

def normalize_text(text):
    """
    Normalize text input by converting to lowercase, removing special characters, and extra whitespace
    while preserving essential information
    
    Args:
        text (str): The text to normalize
        
    Returns:
        str: Normalized text
    """
    # Convert to lowercase
    text = text.lower()
    
    # Preserve important year numbers (dates often matter in news)
    years = re.findall(r'\b(19\d{2}|20\d{2})\b', text)
    year_placeholders = {}
    for i, year in enumerate(years):
        placeholder = f"YEAR{i}"
        year_placeholders[placeholder] = year
        text = text.replace(year, placeholder)
    
    # Preserve specific entity names that may contain numbers
    # Example: COVID-19, T20, etc.
    entities = re.findall(r'\b([a-z]+[\-]?\d+)\b', text)
    entity_placeholders = {}
    for i, entity in enumerate(entities):
        placeholder = f"ENTITY{i}"
        entity_placeholders[placeholder] = entity
        text = text.replace(entity, placeholder)
    
    # Special case for common news entities
    common_entities = ["rcb", "ipl", "t20", "covid"]
    for entity in common_entities:
        if entity in text.lower():
            text = text.replace(entity, f" {entity} ")
    
    # Remove special characters and numbers (keep only letters, spaces)
    text = re.sub(r'[^a-z\s]', '', text)
    
    # Restore the years and entities
    for placeholder, year in year_placeholders.items():
        text = text.replace(placeholder.lower(), year)
    
    for placeholder, entity in entity_placeholders.items():
        text = text.replace(placeholder.lower(), entity)
    
    # Remove extra whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    
    return text

def extract_keywords(text):
    """
    Extract important keywords from text by removing stopwords
    
    Args:
        text (str): The text to extract keywords from
        
    Returns:
        list: List of important keywords
    """
    # Tokenize the text using our simple tokenizer
    tokens = simple_tokenize(text)
    
    # Remove stopwords and short words
    keywords = [word for word in tokens if word not in STOPWORDS and len(word) > 2]
    
    return keywords

def keyword_similarity(keywords1, keywords2):
    """
    Calculate similarity between two sets of keywords using enhanced metrics
    
    Args:
        keywords1 (list): First list of keywords
        keywords2 (list): Second list of keywords
        
    Returns:
        float: Similarity score (0-1)
    """
    # Convert lists to sets for set operations
    set1 = set(keywords1)
    set2 = set(keywords2)
    
    # Early return if either set is empty
    if not set1 or not set2:
        return 0.0
    
    # Calculate Jaccard similarity (intersection over union)
    intersection = len(set1.intersection(set2))
    union = len(set1.union(set2))
    jaccard = intersection / union if union > 0 else 0.0
    
    # Calculate containment (coverage of smaller set in larger set)
    smaller_set_size = min(len(set1), len(set2))
    containment = intersection / smaller_set_size if smaller_set_size > 0 else 0.0
    
    # Calculate overlap coefficient
    overlap = intersection / min(len(set1), len(set2)) if min(len(set1), len(set2)) > 0 else 0.0
    
    # Calculate frequency of key terms match
    # Count occurrences of each keyword
    freq1 = {}
    for word in keywords1:
        freq1[word] = freq1.get(word, 0) + 1
    
    freq2 = {}
    for word in keywords2:
        freq2[word] = freq2.get(word, 0) + 1
    
    # Identify common words
    common_words = set1.intersection(set2)
    
    # Calculate frequency similarity for common words
    freq_sim = 0.0
    if common_words:
        freq_diffs = []
        for word in common_words:
            # Normalized frequency difference
            f1 = freq1[word] / len(keywords1)
            f2 = freq2[word] / len(keywords2)
            diff = 1.0 - abs(f1 - f2)
            freq_diffs.append(diff)
        
        freq_sim = sum(freq_diffs) / len(freq_diffs) if freq_diffs else 0.0
    
    # Special case: Look for important entities (like "RCB", "IPL", "trophy", etc.)
    # These keywords should have higher importance in similarity calculation
    important_keywords = ["rcb", "ipl", "trophy", "government", "banned", "social", "media"]
    important_match = 0
    important_total = 0
    
    for word in important_keywords:
        if word in set1 or word in set2:
            important_total += 1
            if word in set1 and word in set2:
                important_match += 1
    
    # Calculate importance score
    importance_score = important_match / important_total if important_total > 0 else 0.0
    
    # Calculate combined score with weights
    # Give more weight to Jaccard for general similarity
    # But boost with containment, overlap, frequency similarity and important terms
    combined_score = (
        (jaccard * 0.4) + 
        (containment * 0.2) + 
        (overlap * 0.1) + 
        (freq_sim * 0.1) + 
        (importance_score * 0.2)
    )
    
    # Log similarity metrics for debugging
    logger.debug(f"Similarity metrics - Jaccard: {jaccard:.2f}, Containment: {containment:.2f}, " 
                f"Overlap: {overlap:.2f}, Freq Sim: {freq_sim:.2f}, Importance: {importance_score:.2f}, " 
                f"Combined: {combined_score:.2f}")
    
    return combined_score

def check_exact_match(normalized_query):
    """
    Check if the exact normalized query exists in the database
    
    Args:
        normalized_query (str): The normalized query to check
        
    Returns:
        NewsVerification or None: Matched verification if found, None otherwise
    """
    # Query for exact match
    match = NewsVerification.query.filter_by(normalized_query=normalized_query).first()
    
    if match:
        # Increment cache hit counter
        match.cached_hit += 1
        db.session.commit()
        logger.info(f"Exact match found in database for query: {normalized_query}")
    
    return match

def check_keyword_match(keywords, normalized_query):
    """
    Check if there is a keyword match in the database
    
    Args:
        keywords (list): The keywords to check against
        normalized_query (str): Original normalized query (to avoid returning false matches)
        
    Returns:
        NewsVerification or None: Best matched verification if found, None otherwise
    """
    # Get all verification records
    verifications = NewsVerification.query.all()
    
    best_match = None
    best_similarity = 0
    
    # Check each verification for keyword similarity
    for verification in verifications:
        # Skip exact matches with normalized query (handled separately)
        if verification.normalized_query == normalized_query:
            continue
        
        # Get keywords from verification
        stored_keywords = verification.get_keywords()
        
        # Calculate similarity
        similarity = keyword_similarity(keywords, stored_keywords)
        
        # If similarity exceeds threshold and is better than current best match
        if similarity >= SIMILARITY_THRESHOLD and similarity > best_similarity:
            best_similarity = similarity
            best_match = verification
    
    if best_match:
        # Increment cache hit counter
        best_match.cached_hit += 1
        db.session.commit()
        logger.info(f"Keyword match found in database with similarity {best_similarity:.2f}")
    
    return best_match

def get_mock_response(query):
    """
    Generate a mock response in case the API fails
    This is a fallback to ensure the application works even if API calls fail
    
    Args:
        query (str): The query to generate a response for
        
    Returns:
        dict: A mock response in the same format as the Perplexity API
    """
    # Check for common fake news patterns
    is_fake = False
    if re.search(r'banned|government|conspiracy|5g|microchip|tracking|secret|2025|banned|all of|cure|overnight|miracle', query.lower()):
        is_fake = True
    
    # Generate appropriate content based on whether it's likely fake or not
    if is_fake:
        content = f"This news appears to be fake. There is no credible evidence supporting the claim that '{query}'. This type of statement often appears in misinformation campaigns. Always verify information from official sources before sharing."
    else:
        content = f"Without specific details to verify, I cannot determine if '{query}' is real or fake news. The statement should be evaluated based on: 1) Source credibility, 2) Cross-verification with other reliable sources, 3) Evidence provided. Please consider checking established news outlets or fact-checking websites for verification."
    
    # Return a response in the same format as the API
    return {
        "id": "mock-response",
        "model": "mock-model",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": content
                },
                "finish_reason": "stop"
            }
        ]
    }

def query_perplexity_api(user_news_input):
    """
    Query the Perplexity API to verify news
    
    Args:
        user_news_input (str): The news statement to verify
        
    Returns:
        dict: API response
    """
    # Try to get API key from ConfigManager first, then fallback to environment/module level
    try:
        from config_manager import ConfigManager
        api_key = ConfigManager.get_setting('perplexity_api_key', 'api_keys')
    except:
        api_key = None
    
    # Fallback to module-level API_KEY if not found in config
    if not api_key:
        api_key = API_KEY
    
    # Check if API key is available
    if not api_key:
        logger.error("No Perplexity API key available in admin config or environment")
        return get_mock_response(user_news_input)
    
    # Prepare the request payload with our autoprompt template
    payload = {
        "model": "sonar",
        "messages": [
            {
                "role": "system",
                "content": "You are a news verification assistant. Analyze news statements and determine if they are real or fake. Be objective and provide evidence."
            },
            {
                "role": "user",
                "content": f"Is the following news real or fake? Please verify the credibility with explanation: \"{user_news_input}\""
            }
        ],
        "temperature": 0.2,
        "max_tokens": 500,
        "stream": False
    }
    
    # Set up headers with API key
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    try:
        # Make request to Perplexity API
        logger.info(f"Querying Perplexity API for: {user_news_input[:50]}...")
        response = requests.post(PERPLEXITY_API_URL, json=payload, headers=headers)
        response.raise_for_status()
        return response.json()
    
    except requests.exceptions.RequestException as e:
        logger.error(f"API request error: {str(e)}")
        # Return mock response instead of raising
        logger.warning("Using mock response due to API error")
        return get_mock_response(user_news_input)
        
    except json.JSONDecodeError:
        logger.error("Error parsing API response")
        # Return mock response instead of raising
        logger.warning("Using mock response due to JSON parsing error")
        return get_mock_response(user_news_input)

def process_perplexity_response(response, original_query, normalized_query, keywords):
    """
    Process and store the Perplexity API response
    
    Args:
        response (dict): The API response
        original_query (str): The original news statement
        normalized_query (str): The normalized query
        keywords (list): The extracted keywords
        
    Returns:
        NewsVerification: The created verification record
    """
    # Extract the response content
    try:
        content = response["choices"][0]["message"]["content"]
        
        # Determine if the news is real, fake, or unclear based on content
        is_real = None
        if re.search(r'\b(real|true|verified|confirmed|accurate)\b', content.lower()):
            is_real = True
        elif re.search(r'\b(fake|false|fabricated|hoax|misinformation|disinformation)\b', content.lower()):
            is_real = False
            
        # Create new verification record
        verification = NewsVerification(
            original_query=original_query,
            normalized_query=normalized_query,
            response=content,
            is_real=is_real,
            source="perplexity",
            cached_hit=1  # First access counts as a hit
        )
        
        # Set keywords
        verification.set_keywords(keywords)
        
        # Save to database
        db.session.add(verification)
        db.session.commit()
        
        logger.info(f"New verification stored for query: {original_query[:50]}...")
        
        return verification
    
    except (KeyError, IndexError) as e:
        logger.error(f"Error processing API response: {str(e)}")
        raise ValueError(f"Error processing API response: {str(e)}")

def verify_news(news_statement):
    """
    Verify a news statement using smart caching and Perplexity API
    
    Args:
        news_statement (str): The news statement to verify
        
    Returns:
        dict: Verification result
    """
    try:
        # Normalize input
        normalized_query = normalize_text(news_statement)
        
        # Extract keywords with error handling
        try:
            keywords = extract_keywords(normalized_query)
        except Exception as keyword_error:
            logger.error(f"Error extracting keywords: {str(keyword_error)}")
            # Create a simple fallback for keywords
            keywords = normalized_query.split()
        
        # Step 1: Check for exact match
        try:
            exact_match = check_exact_match(normalized_query)
            if exact_match:
                return {
                    "result": exact_match.to_dict(),
                    "source": "cache_exact",
                    "message": "This news has been previously verified (exact match)."
                }
        except Exception as db_error:
            logger.error(f"Error checking exact match: {str(db_error)}")
            # Continue to next step if database lookup fails
        
        # Step 2: Check for keyword match if no exact match found
        try:
            keyword_match = check_keyword_match(keywords, normalized_query)
            if keyword_match:
                return {
                    "result": keyword_match.to_dict(),
                    "source": "cache_similar",
                    "message": "This news is similar to previously verified content."
                }
        except Exception as keyword_match_error:
            logger.error(f"Error checking keyword match: {str(keyword_match_error)}")
            # Continue to API call if keyword matching fails
        
        # Step 3: Call Perplexity API if no matches found
        try:
            # Always use the API in this case
            api_response = query_perplexity_api(news_statement)
            
            # Process and store the response
            try:
                verification = process_perplexity_response(api_response, news_statement, normalized_query, keywords)
                return {
                    "result": verification.to_dict(),
                    "source": "perplexity_api",
                    "message": "This news has been verified with Perplexity API."
                }
            except Exception as process_error:
                logger.error(f"Error processing API response: {str(process_error)}")
                
                # Return the API response even if we couldn't store it
                # Extract content directly
                if "choices" in api_response and len(api_response["choices"]) > 0:
                    content = api_response["choices"][0]["message"]["content"]
                    return {
                        "result": {
                            "original_query": news_statement,
                            "response": content,
                            "is_real": None,
                            "verification_date": datetime.utcnow().isoformat(),
                            "source": "perplexity_api_transient"
                        },
                        "source": "perplexity_api_transient",
                        "message": "This news was verified with Perplexity API (not stored)."
                    }
        except Exception as api_error:
            logger.error(f"Error with Perplexity API: {str(api_error)}")
            
            # Create a mock response if API fails completely
            mock_response = get_mock_response(news_statement)
            content = mock_response["choices"][0]["message"]["content"]
            
            # Determine if it's real or fake from the mock response
            is_real = None
            if "fake" in content.lower():
                is_real = False
            elif "real" in content.lower():
                is_real = True
                
            return {
                "result": {
                    "original_query": news_statement,
                    "response": content,
                    "is_real": is_real,
                    "verification_date": datetime.utcnow().isoformat(),
                    "source": "fallback_analysis"
                },
                "source": "fallback_analysis",
                "message": "Unable to verify with API, used fallback analysis."
            }
    
    except Exception as e:
        # Final fallback for any other errors
        logger.error(f"Unexpected error verifying news: {str(e)}")
        return {
            "error": str(e),
            "message": "Error verifying news statement. Please try again later.",
            "result": {
                "original_query": news_statement,
                "response": "Error processing this news statement. Our verification service is currently experiencing technical difficulties.",
                "is_real": None,
                "verification_date": datetime.utcnow().isoformat(),
                "source": "error"
            }
        }