import os
import logging
from flask import Flask, render_template, request, jsonify, redirect, url_for
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from safebrowsing import check_url_safety
from news_verification import verify_news
from ad_verification import verify_ad
from company_verification import verify_company
import urllib.parse
from models import db, URLCheck, NewsVerification, AdVerification, CompanyVerification
from sqlalchemy import desc
from datetime import datetime
from ocr_processor import process_image
from config import config, init_redis
from admin_panel import admin_panel
from admin_middleware import AdminMiddleware, setup_admin_session_config
from rate_limiter import RateLimitManager, init_rate_limiting, rate_limit_exceeded_handler
from config_manager import init_config_management
from monitoring_service import init_monitoring, monitor_request
from maintenance_mode import init_maintenance_mode
from admin_error_handler import init_admin_error_handling

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create Flask application
app = Flask(__name__)

# Load configuration
config_name = os.environ.get('FLASK_ENV', 'development')
app.config.from_object(config[config_name])

# Initialize Redis
init_redis(app)

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri=app.config['RATELIMIT_STORAGE_URI'],
    strategy=app.config['RATELIMIT_STRATEGY'],
    headers_enabled=app.config['RATELIMIT_HEADERS_ENABLED'],
    default_limits=["1000 per hour", "100 per minute"]
)

# Initialize the database
db.init_app(app)

# Register admin panel blueprint
app.register_blueprint(admin_panel)

# Initialize admin middleware and session config
AdminMiddleware(app)
setup_admin_session_config(app)

# Initialize rate limiting
init_rate_limiting(app)

# Initialize configuration management
init_config_management(app)

# Initialize monitoring
init_monitoring(app)

# Initialize maintenance mode
init_maintenance_mode(app)

# Initialize admin error handling
init_admin_error_handling(app)

# Set up rate limit error handler
app.errorhandler(429)(rate_limit_exceeded_handler)

# Create all database tables
with app.app_context():
    db.create_all()
    
    # Add mock verification data for testing
    # Add mock ad verification data if table is empty
    if AdVerification.query.count() == 0:
        logger.info("Adding mock ad verification data")
        
        # Example 1: Mock iPhone free giveaway ad
        mock_iphone_ad = AdVerification(
            original_ad="🔥 Hurry! Get Free iPhones from Apple! Limited time offer!",
            normalized_ad="hurry get free iphones from apple limited time offer",
            response="This advertisement is misleading. Apple does not offer free iPhones through unsolicited promotions. Be cautious of ads claiming to give away free high-value products as they are typically scams designed to collect personal information or install malware.",
            is_trustworthy=False,
            source="perplexity",
            mentioned_company="Apple",
            cached_hit=0
        )
        mock_iphone_ad.set_keywords(["hurry", "free", "iphones", "apple", "limited", "time", "offer"])
        
        # Example 2: Legitimate discount ad
        mock_amazon_ad = AdVerification(
            original_ad="Amazon Prime Day: Save up to 50% on select electronics. Shop now at amazon.com/primeday",
            normalized_ad="amazon prime day save up to 50 on select electronics shop now at amazoncomprimeday",
            response="This appears to be a legitimate advertisement for Amazon Prime Day, which is a real shopping event that Amazon runs periodically. The 50% discount on select electronics is a common promotional offer during these events.",
            is_trustworthy=True,
            source="perplexity",
            mentioned_company="Amazon",
            cached_hit=0
        )
        mock_amazon_ad.set_keywords(["amazon", "prime", "day", "save", "50", "select", "electronics", "shop"])
        
        # Example 3: Suspicious giveaway
        mock_giveaway_ad = AdVerification(
            original_ad="ATTENTION! You've been selected to receive a $1000 Walmart gift card! Click here to claim your prize now! www.claim-your-reward-now.com",
            normalized_ad="attention youve been selected to receive a 1000 walmart gift card click here to claim your prize now wwwclaimyourrewardnowcom",
            response="This advertisement is highly suspicious and likely fraudulent. Legitimate companies like Walmart do not randomly select people for large gift card giveaways. The domain 'claim-your-reward-now.com' is not affiliated with Walmart and is a red flag for a potential scam or phishing attempt.",
            is_trustworthy=False,
            source="perplexity",
            mentioned_company="Walmart",
            cached_hit=0
        )
        mock_giveaway_ad.set_keywords(["attention", "selected", "receive", "1000", "walmart", "gift", "card", "claim", "prize"])
        
        # Add the mock ad entries to the database
        db.session.add(mock_iphone_ad)
        db.session.add(mock_amazon_ad)
        db.session.add(mock_giveaway_ad)
        db.session.commit()
        logger.info("Added mock ad verification data successfully")
    
    # Add mock company verification data if table is empty
    if CompanyVerification.query.count() == 0:
        logger.info("Adding mock company verification data")
        
        # Example 1: Mock Microsoft company verification
        mock_microsoft = CompanyVerification(
            company_name="Microsoft Corporation",
            normalized_name="microsoft",
            response="Microsoft Corporation is a legitimate, registered company founded in 1975. It is one of the world's largest technology companies and is publicly traded on NASDAQ. The company's claims about its products and services are generally verified and credible.",
            is_registered=True,
            claims_verified=True,
            source="perplexity",
            cached_hit=0
        )
        mock_microsoft.set_keywords(["microsoft"])
        
        # Example 2: Mock Apple Inc. company verification
        mock_apple = CompanyVerification(
            company_name="Apple Inc.",
            normalized_name="apple",
            response="Apple Inc. is a legitimate, publicly traded company founded in 1976. It is one of the world's most valuable technology companies, traded on NASDAQ under the ticker AAPL. The company's claims about its products and services are generally verified and supported by evidence.",
            is_registered=True,
            claims_verified=True,
            source="perplexity",
            cached_hit=0
        )
        mock_apple.set_keywords(["apple"])
        
        # Example 3: Suspicious company verification
        mock_suspicious = CompanyVerification(
            company_name="Super Fast Money LLC",
            normalized_name="super fast money",
            response="There is limited verifiable information about 'Super Fast Money LLC'. No registration details could be found in standard business databases. The company makes claims about guaranteed investment returns that cannot be verified and are typical of fraudulent investment schemes.",
            is_registered=False,
            claims_verified=False,
            source="perplexity",
            cached_hit=0
        )
        mock_suspicious.set_keywords(["super", "fast", "money"])
        
        # Add the mock company entries to the database
        db.session.add(mock_microsoft)
        db.session.add(mock_apple)
        db.session.add(mock_suspicious)
        db.session.commit()
        logger.info("Added mock company verification data successfully")

@app.route('/')
def index():
    """Render the main page of the application."""
    return render_template('index.html')

@app.route('/news')
def news():
    """Render the news verification page."""
    return render_template('news.html')

@app.route('/ads')
def ads():
    """Render the ads verification page."""
    return render_template('ads.html')

@app.route('/company')
def company():
    """Render the company verification page."""
    return render_template('company.html')

@app.route('/check', methods=['POST'])
@limiter.limit("50 per minute")
@monitor_request
def check_url():
    """
    Endpoint to check if a URL is safe using Google Safe Browsing API.
    
    Returns:
        JSON response with safety status and details
    """
    # Get URL from request (support both JSON and form data)
    if request.is_json:
        data = request.get_json()
        url = data.get('url', '').strip() if data else ''
    else:
        url = request.form.get('url', '').strip()
    
    if not url:
        return jsonify({
            'status': 'error',
            'message': 'Please enter a URL'
        }), 400
    
    # Validate URL format
    try:
        parsed_url = urllib.parse.urlparse(url)
        if not parsed_url.scheme:
            url = 'http://' + url
            parsed_url = urllib.parse.urlparse(url)
            
        if not parsed_url.netloc:
            return jsonify({
                'status': 'error',
                'message': 'Invalid URL format'
            }), 400
    except Exception as e:
        logger.error(f"URL parsing error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Invalid URL format'
        }), 400
    
    # Check URL safety
    try:
        result = check_url_safety(url)
        
        # Store the check result in the database
        ip_address = request.remote_addr
        device_id = request.form.get('device_id', 'unknown')
        
        # Determine if the URL is considered safe
        # 'safe' status is definite safe, 'likely_safe' is also considered safe
        is_safe = result['status'] in ['safe', 'likely_safe']
        
        # Get threat details if any
        threat_type = None
        if result['status'] in ['unsafe', 'caution']:
            threat_type = result.get('details', '')
        
        # Create URL check record
        url_check = URLCheck(
            url=url,
            is_safe=is_safe,
            threat_type=threat_type,
            ip_address=ip_address
        )
        
        db.session.add(url_check)
        db.session.commit()
        
        # Add the check ID to the result for reference
        result['check_id'] = url_check.id
        
        # For UI consistency, map additional statuses to the ones 
        # the frontend expects (safe, unsafe, or caution)
        if result['status'] == 'likely_safe':
            result['ui_status'] = 'safe'
        elif result['status'] == 'caution' or result['status'] == 'unknown':
            result['ui_status'] = 'caution'
        else:
            result['ui_status'] = result['status']
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error checking URL safety: {str(e)}")
        # Use the fallback method directly if there was an error
        fallback_result = {
            'status': 'error',
            'message': 'Unable to check URL safety with Google Safe Browsing API',
            'details': 'Using basic domain analysis instead',
            'recommendation': 'Please verify the URL authenticity from its source.'
        }
        return jsonify(fallback_result), 500

@app.route('/history')
def history():
    """Display history of URL checks"""
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    # Get paginated URL check history
    checks = URLCheck.query.order_by(desc(URLCheck.check_date)).paginate(page=page, per_page=per_page)
    
    return render_template('history.html', checks=checks)

@app.route('/api/history')
def api_history():
    """API endpoint to get URL check history"""
    limit = request.args.get('limit', 10, type=int)
    
    # Get most recent URL checks
    checks = URLCheck.query.order_by(desc(URLCheck.check_date)).limit(limit).all()
    
    # Convert to list of dictionaries
    results = [check.to_dict() for check in checks]
    
    return jsonify({
        'history': results,
        'count': len(results)
    })

@app.route('/clear_history', methods=['POST'])
def clear_history():
    """Clear all URL check history"""
    try:
        db.session.query(URLCheck).delete()
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'History cleared successfully'})
    except Exception as e:
        logger.error(f"Error clearing history: {str(e)}")
        db.session.rollback()
        return jsonify({'status': 'error', 'message': f'Error clearing history: {str(e)}'}), 500

@app.route('/verify_news', methods=['POST'])
@limiter.limit("30 per minute")
@monitor_request
def verify_news_endpoint():
    """
    Endpoint to verify news statements using Perplexity API
    with smart caching for optimization.
    
    Returns:
        JSON response with verification result
    """
    # Get news statement from request (support both JSON and form data)
    if request.is_json:
        data = request.get_json()
        news_statement = data.get('text', '').strip() if data else ''
    else:
        news_statement = request.form.get('news_statement', '').strip()
    
    if not news_statement:
        return jsonify({
            'status': 'error',
            'message': 'Please enter a news statement to verify'
        }), 400
    
    try:
        # Verify news using our verification service
        result = verify_news(news_statement)
        
        # Return verification result
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error verifying news: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Error verifying news: {str(e)}'
        }), 500

@app.route('/news_history')
def news_history():
    """Display history of news verifications"""
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    # Get paginated news verification history
    verifications = NewsVerification.query.order_by(desc(NewsVerification.verification_date)).paginate(page=page, per_page=per_page)
    
    return render_template('news_history.html', verifications=verifications)

@app.route('/api/news_history')
def api_news_history():
    """API endpoint to get news verification history"""
    limit = request.args.get('limit', 10, type=int)
    
    # Get most recent news verifications
    verifications = NewsVerification.query.order_by(desc(NewsVerification.verification_date)).limit(limit).all()
    
    # Convert to list of dictionaries
    results = [verification.to_dict() for verification in verifications]
    
    return jsonify({
        'history': results,
        'count': len(results)
    })

@app.route('/clear_news_history', methods=['POST'])
def clear_news_history():
    """Clear all news verification history"""
    try:
        db.session.query(NewsVerification).delete()
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'News verification history cleared successfully'})
    except Exception as e:
        logger.error(f"Error clearing news history: {str(e)}")
        db.session.rollback()
        return jsonify({'status': 'error', 'message': f'Error clearing news history: {str(e)}'}), 500
        
# Ad verification endpoints
@app.route('/verify_ad', methods=['POST'])
@limiter.limit("30 per minute")
@monitor_request
def verify_ad_endpoint():
    """
    Endpoint to verify advertisement content using Perplexity API
    with smart caching for optimization.
    
    Returns:
        JSON response with verification result
    """
    logger.info("Ad verification endpoint called")
    
    # Log all form data to debug
    logger.debug(f"Request form data: {request.form}")
    logger.debug(f"Request method: {request.method}")
    logger.debug(f"Request content type: {request.content_type}")
    
    # Get ad text from request
    ad_text = request.form.get('ad_text', '').strip()
    
    logger.info(f"Received ad verification request with text: {ad_text[:50]}...")
    
    if not ad_text:
        logger.error("Empty ad text received in verify_ad_endpoint")
        return jsonify({
            'status': 'error',
            'message': 'Please enter an advertisement to verify'
        }), 400
    
    try:
        # Verify ad using our verification service
        logger.info(f"Calling verify_ad function with ad text: {ad_text[:50]}...")
        result = verify_ad(ad_text)
        
        # Return verification result
        logger.info(f"Ad verification successful, returning result with status: {result.get('status')}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error verifying ad: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({
            'status': 'error',
            'message': f'Error verifying advertisement: {str(e)}'
        }), 500

@app.route('/ads_history')
def ads_history():
    """Display history of ad verifications"""
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    # Get paginated ad verification history
    verifications = AdVerification.query.order_by(desc(AdVerification.verification_date)).paginate(page=page, per_page=per_page)
    
    return render_template('ads_history.html', verifications=verifications)

@app.route('/api/ads_history')
def api_ads_history():
    """API endpoint to get ad verification history"""
    limit = request.args.get('limit', 10, type=int)
    
    # Get most recent ad verifications
    verifications = AdVerification.query.order_by(desc(AdVerification.verification_date)).limit(limit).all()
    
    # Convert to list of dictionaries
    results = [verification.to_dict() for verification in verifications]
    
    return jsonify({
        'history': results,
        'count': len(results)
    })

@app.route('/clear_ads_history', methods=['POST'])
def clear_ads_history():
    """Clear all ad verification history"""
    try:
        db.session.query(AdVerification).delete()
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Advertisement verification history cleared successfully'})
    except Exception as e:
        logger.error(f"Error clearing ad history: {str(e)}")
        db.session.rollback()
        return jsonify({'status': 'error', 'message': f'Error clearing ad history: {str(e)}'}), 500

# Company verification endpoints
@app.route('/verify_company', methods=['POST'])
@limiter.limit("30 per minute")
def verify_company_endpoint():
    """
    Endpoint to verify company information using Perplexity API
    with smart caching for optimization.
    
    Returns:
        JSON response with verification result
    """
    logger.info("Company verification endpoint called")
    
    # Log all form data to debug
    logger.debug(f"Request form data: {request.form}")
    logger.debug(f"Request method: {request.method}")
    logger.debug(f"Request content type: {request.content_type}")
    
    # Get company name from request (support both JSON and form data)
    if request.is_json:
        data = request.get_json()
        company_name = data.get('company', '').strip() if data else ''
    else:
        company_name = request.form.get('company_name', '').strip()
    
    logger.info(f"Received company verification request for: {company_name}")
    
    if not company_name:
        logger.error("Empty company name received in verify_company_endpoint")
        return jsonify({
            'status': 'error',
            'message': 'Please enter a company name to verify'
        }), 400
    
    try:
        # Verify company using our verification service
        logger.info(f"Calling verify_company function with: {company_name}")
        result = verify_company(company_name)
        
        # Return verification result
        logger.info(f"Company verification successful, returning result with status: {result.get('status')}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error verifying company: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({
            'status': 'error',
            'message': f'Error verifying company: {str(e)}'
        }), 500

@app.route('/company_history')
def company_history():
    """Display history of company verifications"""
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    # Get paginated company verification history
    verifications = CompanyVerification.query.order_by(desc(CompanyVerification.verification_date)).paginate(page=page, per_page=per_page)
    
    return render_template('company_history.html', verifications=verifications)

@app.route('/api/company_history')
def api_company_history():
    """API endpoint to get company verification history"""
    limit = request.args.get('limit', 10, type=int)
    
    # Get most recent company verifications
    verifications = CompanyVerification.query.order_by(desc(CompanyVerification.verification_date)).limit(limit).all()
    
    # Convert to list of dictionaries
    results = [verification.to_dict() for verification in verifications]
    
    return jsonify({
        'history': results,
        'count': len(results)
    })

@app.route('/clear_company_history', methods=['POST'])
def clear_company_history():
    """Clear all company verification history"""
    try:
        db.session.query(CompanyVerification).delete()
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Company verification history cleared successfully'})
    except Exception as e:
        logger.error(f"Error clearing company history: {str(e)}")
        db.session.rollback()
        return jsonify({'status': 'error', 'message': f'Error clearing company history: {str(e)}'}), 500

@app.route('/process_screenshot', methods=['POST'])
@limiter.limit("10 per minute")
def process_screenshot():
    """
    Process screenshot with OCR and route to appropriate verification endpoint
    """
    try:
        # Get data from request
        data = request.get_json()
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'No data provided'
            }), 400

        image_base64 = data.get('image')
        verification_type = data.get('type')  # 'news', 'link', 'ad', or 'company'

        if not image_base64 or not verification_type:
            return jsonify({
                'status': 'error',
                'message': 'Missing required parameters'
            }), 400

        # Process image with OCR
        extracted_text = process_image(image_base64)

        if not extracted_text:
            return jsonify({
                'status': 'error',
                'message': 'No text could be extracted from the image'
            }), 400

        # Route to appropriate verification based on type
        if verification_type == 'news':
            result = verify_news(extracted_text)
        elif verification_type == 'link':
            result = check_url_safety(extracted_text)
        elif verification_type == 'ad':
            result = verify_ad(extracted_text)
        elif verification_type == 'company':
            result = verify_company(extracted_text)
        else:
            return jsonify({
                'status': 'error',
                'message': 'Invalid verification type'
            }), 400

        return jsonify({
            'status': 'success',
            'extracted_text': extracted_text,
            'verification_result': result
        })

    except Exception as e:
        logger.error(f"Error processing screenshot: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Error processing screenshot: {str(e)}'
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
