Features
User Authentication

Register and login functionality with hashed password storage.

Session-based authentication.

Logout support.

Log File Upload

Secure file upload and storage.

Parsing of Zscaler logs (CSV format).

Storage of parsed logs into a PostgreSQL database.

Threat Analysis

Summarizes top threats.

Identifies and lists blocked events with and without threats.

Provides insight into historical blocked logs stored in the database.

📡 API Endpoints
🔐 Authentication
POST /register
Register a new user.
Payload: { "username": "user1", "password": "pass123" }

POST /login
Log in an existing user.
Payload: { "username": "user1", "password": "pass123" }
Response: Sets a session cookie for auth.

GET /check-auth
Check if the user is currently logged in.
Response: { loggedIn: true, user: "user1" } if logged in.

POST /logout
Logout the current user.
Response: Clears session and cookie.

📁 Log Upload & Analysis
POST /upload
Upload a .csv log file.
Form-Data: { file: <your_file.csv> }
Response: Returns uploaded filename.

POST /analyze-zscaler
Parse and analyze the uploaded log file.
Payload: { "filename": "your_file.csv" }
Response: Returns:

Summary of threats.

List of blocked threats.

Note on other blocked events.

GET /analyze-db-logs
Fetch blocked threats from logs already stored in the database.
Response: Array of blocked threat entries.
