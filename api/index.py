from flask import Flask, jsonify
from app import app as flask_app

# Simple health check endpoint
@flask_app.route('/api/health')
def health_check():
    return jsonify({"status": "ok", "service": "ICF Button Backend"})

# Vercel serverless handler
def handler(event, context):
    with flask_app.app_context():
        from flask import request
        from io import BytesIO
        # Convert Vercel event to WSGI environ
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

# For local testing
if __name__ == '__main__':
    flask_app.run(debug=True, port=5000)
            except Exception as e:
                response = flask_app.handle_exception(e)
        return {
            'statusCode': response.status_code,
            'headers': dict(response.headers),
            'body': response.get_data(as_text=True)
        }

# For local testing
if __name__ == '__main__':
    flask_app.run()
