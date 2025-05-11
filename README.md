# Log Analysis 

A full-stack log analysis application. It allows users to securely upload Zscaler-style log files, authenticate, and analyze threats using a Flask-based API server. All parsed logs and analysis results are stored in a PostgreSQL database.

### 🔗 Live Link

[Click here to view the deployed application](https://log-analyzer-frontend.onrender.com/)

#### Since the application is deployed on free tier it may take some time to load initially. The initial login may take a few seconds due to backend cold start on the free-tier deployment

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

### Use of AI/LLM
While developing this assignment, I made use of AI/large language models (LLMs) to assist in specific areas:

**Error Resolution During Deployment:**
I encountered a few issues while deploying the full-stack application (e.g., server errors, environment variable setup, cross-origin request issues). I used AI tools to understand the cause of these errors and solve those errors accordingly.

**React Syntax Reference:**
While working with React (particularly hooks like useEffect, useState, and useNavigate), I occasionally used AI tools to confirm proper syntax or usage patterns when I was unsure or needed quick clarification.

---

<h2> Authentication</h2>

<h3> POST /register</h3>
<p>Register a new user.</p>

<strong>Payload:</strong>
<pre><code class="language-json">
{
  "username": "user1",
  "password": "pass123"
}
</code></pre>

<hr>

<h3>POST /login</h3>
<p>Login a user.</p>

<strong>Payload:</strong>
<pre><code class="language-json">
{
  "username": "user1",
  "password": "pass123"
}
</code></pre>

<strong>Response:</strong>
<ul>
  <li><strong>Status:</strong> 200 OK</li>
  <li><strong>Sets:</strong> A session cookie for authentication.</li>
  <li><strong>Message:</strong> "Login successful" or appropriate error message.</li>
</ul>

<hr>

<h3>GET /check-auth</h3>
<p>Check if the user is currently logged in.</p>

<strong>Example Response:</strong>
<pre><code class="language-json">
{
  "loggedIn": true,
  "user": "user1"
}
</code></pre>

<ul>
  <li><strong>loggedIn:</strong> <code>true</code> if the user is logged in, <code>false</code> otherwise.</li>
  <li><strong>user:</strong> The username of the currently logged-in user.</li>
</ul>
<h2> Log Upload & Analysis</h2>

<h3> POST /upload</h3>
<p>Upload a <code>.txt</code> log file.</p>

<strong>Form-Data:</strong>
<pre><code>file: &lt;your_file.txt&gt;</code></pre>

<strong>Response:</strong>
<pre><code class="language-json">
{
  "filename": "your_file.txt"
}
</code></pre>

<hr>

<h3> POST /analyze-zscaler</h3>
<p>Parse and analyze the uploaded log file.</p>

<strong>Payload:</strong>
<pre><code class="language-json">
{
  "filename": "your_file.txt"
}
</code></pre>

<strong>Response:</strong>
<pre><code class="language-json">
{
  "summary": {
    "Blocked": 10,
  },
  "blocked_threats": [
    {
      "Threat_Name": "Malware",
      "Action": "Blocked"
      // ...
    }
  ],
  "note": "Other blocked events that did not contain known threats."
}
</code></pre>

<ul>
  <li><strong>summary:</strong> Overview of the analysis.</li>
  <li><strong>Blocked:</strong> The number of blocked threats.</li>
  <li><strong>blocked_threats:</strong> A list of blocked threats, including threat name, action, and additional details.</li>
  <li><strong>note:</strong> A note regarding other blocked events that may not be threats.</li>
</ul>

<hr>

<h3> GET /analyze-db-logs</h3>
<p>Fetch blocked threats from logs already stored in the database.</p>

<strong>Response:</strong>
<pre><code class="language-json">
[
  {
    "Action": "Blocked",
    "Threat_Name": "Malware"
    // ...
  }
  // ...
]
</code></pre>

<ul>
  <li>Returns an array of blocked threat entries stored in the database.</li>
  <li>Each entry includes information such as <code>Action</code> (Blocked/Allowed), <code>Threat_Name</code>, and other relevant fields.</li>
</ul>

