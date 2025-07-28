import os
import sys
from flask import Flask, jsonify

# Correct import path (assuming app.py is in root)
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import app as flask_app

@flask_app.route('/api/health')
def health_check():
    return jsonify({"status": "ok"})

def handler(event, context):
    with flask_app.app_context():
        try:
            from flask import request
            from io import BytesIO
            environ = {
                'REQUEST_METHOD': event['httpMethod'],
                'PATH_INFO': event['path'],
                'QUERY_STRING': event.get('queryStringParameters', ''),
                'wsgi.input': BytesIO(event.get('body', '').encode() if event.get('body') else b''),
                'CONTENT_TYPE': event.get('headers', {}).get('content-type', ''),
            }
            with flask_app.request_context(environ):
                response = flask_app.full_dispatch_request()
            return {
                'statusCode': response.status_code,
                'headers': dict(response.headers),
                'body': response.get_data(as_text=True)
            }
        except Exception as e:
            return {
                'statusCode': 500,
                'body': str(e)
            }

if __name__ == '__main__':
    flask_app.run(debug=True, port=5000)
