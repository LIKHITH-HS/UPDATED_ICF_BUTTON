# 📸 OCR Overlay Verification Backend

A powerful Flask-based backend service that provides OCR (Optical Character Recognition) processing and content verification for the Android Overlay Verification App.

## 🚀 Features

### Core OCR Processing
- **Screenshot OCR**: Extract text from screenshots using advanced OCR engines
- **Multiple OCR Engines**: Support for various OCR providers
- **Image Processing**: Automatic image optimization for better OCR accuracy
- **Batch Processing**: Handle multiple images efficiently

### Content Verification
- **URL Verification**: Check URLs for safety and legitimacy using Google Safe Browsing
- **News Verification**: Validate news content authenticity using Perplexity AI
- **Company Verification**: Verify company information
- **Ad Content Analysis**: Analyze advertisement content

### Advanced Features
- **Rate Limiting**: Prevent API abuse with intelligent rate limiting
- **Admin Panel**: Web-based administration interface
- **Monitoring**: Real-time service monitoring and health checks
- **Configuration Management**: Dynamic configuration updates
- **Maintenance Mode**: Graceful service maintenance handling

## 📱 Android App Integration

This backend is specifically designed to work with the **Android Overlay Verification App** that provides:
- Floating OCR button overlay
- Screenshot capture via accessibility service
- Interactive crop selection for precise text extraction
- Real-time OCR processing with backend integration

## 🛠️ Technology Stack

- **Framework**: Flask (Python)
- **OCR Processing**: Tesseract OCR with Pillow image processing
- **Database**: SQLite with SQLAlchemy ORM
- **External APIs**: Google Safe Browsing, Perplexity AI
- **Authentication**: Admin authentication system
- **Deployment**: Production-ready configuration

## 📋 API Endpoints

### OCR Processing
```
POST /process_screenshot
- Process screenshot images for text extraction
- Supports base64 encoded images
- Returns extracted text with confidence scores
- Body: {"image": "base64_data", "type": "screenshot"}
```

### Content Verification
```
POST /check              - URL verification using Safe Browsing
POST /verify_news        - News content verification with Perplexity AI
POST /verify_company     - Company information verification
POST /verify_ad          - Advertisement content analysis
```

### Admin & Monitoring
```
GET  /admin             - Admin panel access
GET  /health            - Service health check
GET  /config            - Configuration management
```

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Tesseract OCR installed on system
- pip or uv package manager

### Installation

1. **Clone the repository**
```bash
git clone <your-repo-url>
cd icf-button-backend
```

2. **Install Tesseract OCR**
```bash
# Windows
winget install UB-Mannheim.TesseractOCR

# Or download from: https://github.com/tesseract-ocr/tesseract
```

3. **Install Python dependencies**
```bash
# Using uv (recommended)
uv sync

# Or using pip
pip install -r requirements.txt
```

4. **Configure environment**
```bash
cp .env.example .env
# Edit .env with your API keys and configuration
```

5. **Run the application**
```bash
# Development
python app.py

# Production
python main.py
```

## ⚙️ Configuration

### Environment Variables
```env
# API Keys
GOOGLE_SAFEBROWSING_API_KEY=your_google_api_key
PERPLEXITY_API_KEY=your_perplexity_api_key

# Database
DATABASE_URL=sqlite:///linksafety.db

# Server Configuration
FLASK_ENV=development
PORT=5000
HOST=0.0.0.0

# Admin Authentication
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your_secure_password

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=3600
```

## 📊 Project Structure

```
├── app.py                     # Main Flask application and API endpoints
├── main.py                    # Production server entry point
├── models.py                  # Database models and schema
├── config_manager.py          # Configuration management
├── ocr_processor.py           # OCR processing logic
├── safebrowsing.py           # URL safety verification
├── news_verification.py      # News content verification
├── company_verification.py   # Company verification logic
├── ad_verification.py        # Advertisement verification
├── admin_panel.py            # Admin interface
├── monitoring_service.py     # Service monitoring
├── rate_limiter.py           # API rate limiting
├── static/                   # Static web assets
├── templates/                # HTML templates
├── android-overlay-app/      # Android application
└── requirements.txt          # Python dependencies
```

## 📱 Android App Features

The companion Android app provides:

### Core Functionality
- **Floating OCR Button**: Always-visible overlay button
- **Screenshot Capture**: Accessibility service-based capture
- **Interactive Cropping**: Precise text area selection
- **Real-time OCR**: Instant text extraction
- **Backend Integration**: Seamless API communication

### User Experience
- **One-time Setup**: Configure accessibility service once
- **Universal Usage**: Works over any app
- **Professional UI**: Clean, modern interface
- **Error Handling**: Robust error management

## 🔒 Security Features

- **Rate Limiting**: Prevent API abuse
- **Input Validation**: Secure input processing
- **Authentication**: Admin panel protection
- **CORS Configuration**: Secure cross-origin requests
- **Error Handling**: Secure error responses
- **API Key Management**: Secure credential handling

## 🧪 Testing

### Run Tests
```bash
# Integration tests
python admin_integration_test.py

# Health checks
python redis_check.py

# Manual API testing
curl -X POST http://localhost:5000/process_screenshot \
  -H "Content-Type: application/json" \
  -d '{"image": "base64_image_data", "type": "screenshot"}'
```

## 📈 Performance Features

- **Image Optimization**: Automatic image processing for better OCR
- **Smart Caching**: Intelligent result caching
- **Connection Pooling**: Optimized database connections
- **Async Processing**: Non-blocking operations where possible
- **Error Recovery**: Robust error handling and recovery

## 🚀 Deployment

### Development
```bash
python app.py
```

### Production
```bash
python main.py
```

### Docker (Optional)
```bash
docker build -t ocr-backend .
docker run -p 5000:5000 ocr-backend
```

## 🤝 Integration Guide

### Android App Setup
1. **Install APK**: Install the Android overlay app
2. **Enable Accessibility**: Grant accessibility service permission
3. **Configure Backend**: Set your backend URL in app settings
4. **Start Overlay**: Launch the floating OCR button
5. **Use OCR**: Tap button → crop → extract text

### API Integration
```javascript
// Example API call
const response = await fetch('/process_screenshot', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    image: base64ImageData,
    type: 'screenshot'
  })
});
const result = await response.json();
```

## 📄 License

This project is licensed under the MIT License.

## 🆘 Support

For support and questions:
- Create an issue in this repository
- Check the admin panel for service status
- Review application logs for troubleshooting

## 🔄 Recent Updates

### Latest Version Features
- ✅ Advanced OCR processing with Tesseract
- ✅ Android overlay app with accessibility service
- ✅ Interactive screenshot cropping
- ✅ Real-time text extraction
- ✅ Comprehensive admin panel
- ✅ Production-ready deployment
- ✅ Rate limiting and security
- ✅ Multi-engine verification support

---

**LinkSafetyShield** - Professional OCR and content verification backend with seamless Android integration.