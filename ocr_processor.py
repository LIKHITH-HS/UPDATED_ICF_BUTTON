import pytesseract
from PIL import Image
import io
import base64
import logging

logger = logging.getLogger(__name__)

def process_image(image_base64):
    """
    Process image with OCR to extract text
    Args:
        image_base64 (str): Base64 encoded image string
    Returns:
        str: Extracted text from image
    """
    try:
        # Decode base64 image
        image_data = base64.b64decode(image_base64)
        image = Image.open(io.BytesIO(image_data))
        
        # Extract text using pytesseract
        text = pytesseract.image_to_string(image)
        
        return text.strip()
    except Exception as e:
        logger.error(f"Error processing image: {str(e)}")
        raise
