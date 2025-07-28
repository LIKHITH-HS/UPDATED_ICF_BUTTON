from flask import Flask, jsonify, Request
from werkzeug.wrappers import Response
from werkzeug.serving import run_simple
import sys

app = Flask(__name__)

@app.route('/health')
def health():
    return jsonify({"status": "OK", "version": "1.0"})

# Vercel Python serverless handler
def handler(request):
    try:
        with app.request_context(request.environ):
            response = app.full_dispatch_request()
            return response
    except Exception as e:
        # Log the error and return a 500 response
        import traceback
        print("Exception in handler:", e)
        traceback.print_exc()
        return Response("Internal Server Error: " + str(e), status=500)

if __name__ == "__main__":
    app.run(debug=True, port=5000)