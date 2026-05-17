# Secure Web Application – [ServerAppProject]
\---

## Description
A secure web application developed as part of the Application Security and Secure Code course. This app
demonstrates secure coding practices including authentication, input validation, encryption, role-based
access control, and threat modeling.
---

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
- User Registration/Login
- Role-based access: Admin/User
- Session management
- Password hashing using bcrypt
- Encryption of sensitive data
- Input validation and sanitization
- STRIDE & DREAD security modeling
- Code scanning using CodeQL
---

\---

## Security Implementations
- Input Validation: [e.g., validator.js]
- Output Sanitization: [e.g., DOMPurify]
- Password Hashing: bcrypt
- Encryption: AES for sensitive fields
- Session Management: [e.g., JWT expiry, cookie flags]
- Headers: Helmet for CSP, XSS protection
- CORS and rate limiting setup
- Role-based Authorization
---

## Threat Modeling
See docs/STRIDE_Threat_Model.md`
See docs/DREAD_Risk_Assessment.md`
---

## Code Scanning Tools Used
- [ ] GitHub CodeQL


## Setup Instructions

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/TimurPheonix/Application-Security-Project.git](https://github.com/TimurPheonix/Application-Security-Project.git)
   cd Application-Security-Project
   
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
JWT_SECRET=your_secret_key_here
PORT=3000
```

### 5\. Start the server

```bash
node server.js
```

### 6\. Open the app

Open `ApplicationProject02.html` in your browser.

```

---
> Passwords are bcrypt hashed in the database.

---

## 





