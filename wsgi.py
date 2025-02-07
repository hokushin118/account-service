"""
WSGI Entry Point - for production servers
"""
from service import app  # Import Flask application

# This is only entered when running this file directly for testing.
# It ensures that app.run() is only called when you run the wsgi.py
# file directly (for development/testing), not when the application
# is imported by a WSGI server.
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
# For WSGI servers: (This is what the WSGI server will use)
# Important: The WSGI server expects a variable named 'application'
application = app
