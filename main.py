from app import app  # noqa: F401

if __name__ == "__main__":
    # Initialize the database on startup
    with app.app_context():
        from models import db
        db.create_all()
    
    # Run the application
    app.run(host="0.0.0.0", port=5000, debug=True)
