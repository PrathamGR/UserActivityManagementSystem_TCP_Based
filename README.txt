User Activity Management System
===============================

Overview:
---------
A Flask-based web application for managing users, login sessions, and user activities with role-based dashboards. The system includes registration, login, admin monitoring, and message viewing functionalities.

Folder Structure:
-----------------
UserActivityManagementSystem/
├── app.py                      # Main Flask app
├── database.db                 # Primary SQLite database
├── instance/database.db        # (Backup or copied DB instance)
├── requirements.txt            # Python dependencies
├── templates/                  # HTML templates (login, register, dashboard, admin, etc.)
├── static/css/style.css        # Frontend styling
├── venv/                       # Python virtual environment (optional in your local setup)

Setup Instructions:
-------------------
1. **(Recommended) Create a new virtual environment**

   On macOS/Linux:
       python3 -m venv venv
       source venv/bin/activate

   On Windows:
       python -m venv venv
       venv\Scripts\activate

2. **Install dependencies**
       pip install -r requirements.txt

3. **Run the Flask application**
       python app.py

4. **Access the app**
       Open your browser and go to: http://127.0.0.1:5000/

Features:
---------
- User registration and login system
- Admin dashboard for monitoring users and activities
- Role-based page rendering
- Viewable message logs
- SQLite database for persistent storage
- Clean and responsive frontend UI

File Notes:
-----------
- `database.db`: Stores all user credentials, roles, and message logs
- `templates/`: Contains HTML files used by Flask (e.g., `login.html`, `admin.html`, `dashboard.html`)
- `static/`: CSS for the frontend UI

Important:
----------
- You can modify credentials or inspect data using DB Browser for SQLite.
- Do not run directly from the ZIP. Extract to a clean folder and set up the virtual environment outside the included `venv/` if present.
- Avoid committing `venv/` to version control — it’s better to create a fresh environment using the included `requirements.txt`.

