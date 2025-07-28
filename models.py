from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
import json

db = SQLAlchemy()

class URLCheck(db.Model):
    """Model for storing URL check history"""
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(2048), nullable=False)
    is_safe = db.Column(db.Boolean, nullable=False)
    threat_type = db.Column(db.String(255), nullable=True)
    check_date = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45), nullable=True)
    device_id = db.Column(db.String(50), nullable=True)  # Device fingerprint for cost optimization
    
    def __repr__(self):
        return f'<URLCheck {self.url} ({"Safe" if self.is_safe else "Unsafe"})>'
    
    def to_dict(self):
        """Convert model to dictionary"""
        return {
            'id': self.id,
            'url': self.url,
            'is_safe': self.is_safe,
            'threat_type': self.threat_type,
            'check_date': self.check_date.isoformat() if self.check_date else None,
            'ip_address': self.ip_address
        }


class NewsVerification(db.Model):
    """Model for storing verified news statements with smart caching"""
    id = db.Column(db.Integer, primary_key=True)
    original_query = db.Column(db.Text, nullable=False)
    normalized_query = db.Column(db.Text, nullable=False, index=True)
    keywords = db.Column(db.Text, nullable=False)  # Stored as JSON string
    response = db.Column(db.Text, nullable=False)
    is_real = db.Column(db.Boolean, nullable=True)  # True for real, False for fake, None for unclear
    verification_date = db.Column(db.DateTime, default=datetime.utcnow)
    source = db.Column(db.String(50), default="perplexity")  # Where the verification came from
    cached_hit = db.Column(db.Integer, default=0)  # Number of times this cache was hit

    def __repr__(self):
        return f"<NewsVerification id={self.id}, query='{self.original_query[:30]}...', is_real={self.is_real}>"
    
    def set_keywords(self, keyword_list):
        """Set keywords as JSON string"""
        self.keywords = json.dumps(keyword_list)
    
    def get_keywords(self):
        """Get keywords as Python list"""
        return json.loads(self.keywords)
    
    def to_dict(self):
        """Convert model to dictionary"""
        return {
            "id": self.id,
            "original_query": self.original_query,
            "normalized_query": self.normalized_query,
            "keywords": self.get_keywords(),
            "response": self.response,
            "is_real": self.is_real,
            "verification_date": self.verification_date.isoformat() if self.verification_date else None,
            "source": self.source,
            "cached_hit": self.cached_hit
        }


class AdVerification(db.Model):
    """Model for storing ad verification with caching"""
    id = db.Column(db.Integer, primary_key=True)
    original_ad = db.Column(db.Text, nullable=False)
    normalized_ad = db.Column(db.Text, nullable=False, index=True)
    keywords = db.Column(db.Text, nullable=False)  # Stored as JSON string
    response = db.Column(db.Text, nullable=False)
    is_trustworthy = db.Column(db.Boolean, nullable=True)  # True for trustworthy, False for misleading, None for unclear
    verification_date = db.Column(db.DateTime, default=datetime.utcnow)
    source = db.Column(db.String(50), default="perplexity")  # Where the verification came from
    cached_hit = db.Column(db.Integer, default=0)  # Number of times this cache was hit
    mentioned_company = db.Column(db.String(255), nullable=True)  # Company name mentioned in the ad

    def __repr__(self):
        return f"<AdVerification id={self.id}, ad='{self.original_ad[:30]}...', is_trustworthy={self.is_trustworthy}>"
    
    def set_keywords(self, keyword_list):
        """Set keywords as JSON string"""
        self.keywords = json.dumps(keyword_list)
    
    def get_keywords(self):
        """Get keywords as Python list"""
        return json.loads(self.keywords)
    
    def to_dict(self):
        """Convert model to dictionary"""
        return {
            "id": self.id,
            "original_ad": self.original_ad,
            "normalized_ad": self.normalized_ad,
            "keywords": self.get_keywords(),
            "response": self.response,
            "is_trustworthy": self.is_trustworthy,
            "verification_date": self.verification_date.isoformat() if self.verification_date else None,
            "source": self.source,
            "cached_hit": self.cached_hit,
            "mentioned_company": self.mentioned_company
        }


class CompanyVerification(db.Model):
    """Model for storing company verification with caching"""
    id = db.Column(db.Integer, primary_key=True)
    company_name = db.Column(db.String(255), nullable=False, index=True)
    normalized_name = db.Column(db.String(255), nullable=False, index=True)
    keywords = db.Column(db.Text, nullable=False)  # Stored as JSON string
    response = db.Column(db.Text, nullable=False)
    is_registered = db.Column(db.Boolean, nullable=True)  # True for registered, False for not registered, None for unclear
    claims_verified = db.Column(db.Boolean, nullable=True)  # True for verified claims, False for unverified claims
    verification_date = db.Column(db.DateTime, default=datetime.utcnow)
    source = db.Column(db.String(50), default="perplexity")  # Where the verification came from
    cached_hit = db.Column(db.Integer, default=0)  # Number of times this cache was hit

    def __repr__(self):
        return f"<CompanyVerification id={self.id}, company='{self.company_name}', is_registered={self.is_registered}>"
    
    def set_keywords(self, keyword_list):
        """Set keywords as JSON string"""
        self.keywords = json.dumps(keyword_list)
    
    def get_keywords(self):
        """Get keywords as Python list"""
        return json.loads(self.keywords)
    
    def to_dict(self):
        """Convert model to dictionary"""
        return {
            "id": self.id,
            "company_name": self.company_name,
            "normalized_name": self.normalized_name,
            "keywords": self.get_keywords(),
            "response": self.response,
            "is_registered": self.is_registered,
            "claims_verified": self.claims_verified,
            "verification_date": self.verification_date.isoformat() if self.verification_date else None,
            "source": self.source,
            "cached_hit": self.cached_hit
        }