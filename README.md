# Log Analysis Backend

This is the backend service for a full-stack log analysis application. It allows users to securely upload Zscaler-style log files, authenticate, and analyze threats using a Flask-based API server. All parsed logs and analysis results are stored in a PostgreSQL database.

---

## Features

###  User Authentication

- **Register and login functionality** with hashed password storage.
- **Session-based authentication.**
- **Logout support.**

### Log File Upload

- **Secure file upload** and storage.
- **Parsing of Zscaler logs**.
- **Storage of parsed logs** into a PostgreSQL database.

### Threat Analysis

- **Summarizes top threats.**
- **Identifies and lists blocked events** with and without threats.
- **Provides insight into historical blocked logs** stored in the database.

---

## API Endpoints

### Authentication

#### `POST /register`
Register a new user.

**Payload:**
```json
{
  "username": "user1",
  "password": "pass123"
}
### `POST /login`
Login a user.

**Payload:**
```json
{
  "username": "user1",
  "password": "pass123"
}
**Response:**
Status: 200 OK
Sets a session cookie for authentication.
Message: Login successful or error mes

### `GET /check-auth`
Check if the user is currently logged in.

**Payload:**
```json
{
  "loggedIn": true,
  "user": "user1"
}
**Response:**
loggedIn: true if the user is logged in, false otherwise.
user: The username of the currently logged-in user.

