from flask import Flask
from werkzeug.middleware.dispatcher import DispatcherMiddleware

# Import your existing app from app.py
from app import app as flask_app

# Vercel serverless handler
def handler(event, context):
    with flask_app.app_context():
        from flask import request
        environ = {
            'REQUEST_METHOD': event['httpMethod'],
            'PATH_INFO': event['path'],
            'QUERY_STRING': event.get('queryStringParameters', {}),
            'wsgi.input': event.get('body', ''),
            'CONTENT_TYPE': event.get('headers', {}).get('Content-Type', ''),
        }
        with flask_app.request_context(environ):
            try:
                response = flask_app.full_dispatch_request()
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
