# Secure Web Application

**Course:** Application Security  
**Department:** CyberSecurity  
**Deadline:** Week 14

\---

## Description

A secure web application built as part of the Application Security course. It demonstrates real-world secure coding practices including JWT authentication, role-based access control, AES encryption, bcrypt hashing, input validation, session management, and threat modeling.

\---

## Tech Stack

|Layer|Technology|
|-|-|
|Frontend|HTML, CSS, Vanilla JavaScript|
|Backend|Node.js + Express.js|
|Database|MongoDB (via Mongoose)|
|Authentication|JWT (jsonwebtoken)|
|Password Hashing|bcryptjs (cost factor 12)|
|Encryption|AES-256-CBC (Node.js crypto)|
|Input Validation|Joi + DOMPurify|

\---

## Features

* User Registration \& Login
* Role-based access: Admin / User
* Admin can view all users and delete them
* Session management with 5-minute timeout and auto-logout
* Login attempt limiting (3 attempts → 30s lockout)
* Last login time tracking via sessionStorage
* Password hashing with bcrypt
* Role field encrypted with AES-256-CBC in MongoDB
* Input validation with Joi on all register fields
* XSS protection with DOMPurify on server + escaping on frontend

\---

## Security Implementations

|Feature|Implementation|
|-|-|
|Authentication|JWT signed token, expires in 5 minutes|
|Authorization|`verifyToken` + `adminOnly` middleware on protected routes|
|Session Management|Frontend countdown timer, auto-logout on expiry, token in memory only|
|Password Hashing|`bcrypt.hash(password, 12)` on register, `bcrypt.compare()` on login|
|Encryption|AES-256-CBC encrypts `role` field before saving to MongoDB|
|Input Validation|Joi schema: alphanum username, min 8 password, enum role|
|Output Sanitization|DOMPurify on server, `\\\\\\\&lt;`/`\\\\\\\&gt;` escaping in table rendering|
|Brute Force Protection|3 failed attempts triggers 30-second lockout|
|Generic Errors|Same error message for wrong username or wrong password|


## Code Scanning Tools Used

* \[x] GitHub CodeQL — static analysis for JS vulnerabilities
* \[x] Snyk — dependency vulnerability scanning
* Reports in [`scans/`](scans/) directory

\---

## Setup Instructions

### 1\. Clone the repository

```bash
git clone https://github.com/YOUR\\\\\\\_USERNAME/YOUR\\\\\\\_REPO.git
cd YOUR\\\\\\\_REPO
```

### 2\. Install dependencies

```bash
npm install
```

### 3\. Make sure MongoDB is running

```bash
mongod
```

### 4\. Create a `.env` file

```
JWT\\\\\\\_SECRET=your\\\\\\\_secret\\\\\\\_key\\\\\\\_here
PORT=3000
```

### 5\. Start the server

```bash
node server.js
```

### 6\. Open the app

Open `ApplicationProject02.html` in your browser.

```

\\\\---

## Test Accounts (MongoDB)

|Username|Role|
|-|-|
|cyberro|Admin|
|cyber|User|
|cyberr|User|

> Passwords are bcrypt hashed in the database.

\\\\---

## 





