const express  = require('express');
const mongoose = require('mongoose');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const cors     = require('cors');
const Joi      = require('joi');
const crypto   = require('crypto'); 
const rateLimit = require('express-rate-limit');
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');

const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

const app = express();
app.use(express.json());
app.use(cors());

require('dotenv').config();
const JWT_SECRET = process.env.JWT_SECRET ;

// ── RATE LIMITING ──────────────────────────────────────
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 5,
    message: { message: 'Too many login attempts. Try again in 15 minutes.' }
});
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { message: 'Too many requests. Please slow down.' }
});
app.use('/login',    loginLimiter);
app.use('/register', apiLimiter);

const algorithm = 'aes-256-cbc';
const key = crypto.scryptSync('mySecretPassword', 'salt', 32); 
const iv = Buffer.alloc(16, 0); 

function encrypt(text) {
    let cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

function decrypt(text) {
    let decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(text, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// ── MONGODB ────────────────────────────────────────────
mongoose.connect('mongodb://localhost:27017/secureDB')
    .then(() => console.log("Connected to MongoDB"))
    .catch(err => console.error("Could not connect", err));

const userSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    role:     { type: String, required: true } 
});

const User = mongoose.model('User', userSchema);

const passwordRegex = /^[^<>'"&%;]*$/; 

const registerSchema = Joi.object({
    username: Joi.string().alphanum().min(3).max(30).required(),
    password: Joi.string().min(8).invalid(Joi.ref('username')).regex(passwordRegex).required().messages({
        'string.pattern.base': 'Password contains forbidden characters or potential XSS payloads.'
    }),
    role: Joi.string().valid('User', 'Admin').required()
});

// ── JWT MIDDLEWARE ─────────────────────────────────────
function verifyToken(req, res, next) {
    const auth = req.headers['authorization'];
    const token = auth && auth.split(' ')[1];
    if (!token) return res.status(401).send({ message: 'No token. Please log in.' });

    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        res.status(403).send({ message: 'Session expired. Please log in again.' });
    }
}

function adminOnly(req, res, next) {
    if (req.user.role !== 'Admin')
        return res.status(403).send({ message: 'Admin access only.' });
    next();
}

// ── REGISTER ──────────────────────────
app.post('/register', async (req, res) => {
    try {
        const rawPassword = req.body.password ? decodeURIComponent(req.body.password) : '';
        const rawUsername = req.body.username ? req.body.username.trim() : '';

        const { error } = registerSchema.validate({
            username: rawUsername,
            password: rawPassword,
            role: req.body.role
        });
        
        if (error) return res.status(400).send({ message: error.details[0].message });

        const exist = await User.findOne({ username: rawUsername });
        if (exist) return res.status(400).send({ message: 'Username already exists.' });

        const hashedPassword = await bcrypt.hash(rawPassword, 12); 
        const encryptedRole = encrypt(req.body.role);

        const newUser = new User({ 
            username: rawUsername, 
            password: hashedPassword, 
            role: encryptedRole 
        });
        
        await newUser.save();
        res.status(201).send({ message: 'User created successfully' });
    } catch (err) {
        res.status(400).send({ message: 'Error creating user.' });
    }
});

// ── LOGIN ──────────────────────────
app.post('/login', async (req, res) => {
    try {
        const rawPassword = req.body.password ? decodeURIComponent(req.body.password) : '';
        const rawUsername = req.body.username ? req.body.username.trim() : '';
        
        const user = await User.findOne({ username: rawUsername });

        if (!user || !(await bcrypt.compare(rawPassword, user.password)))
            return res.status(401).send({ message: 'Invalid credentials.' });

        const decryptedRole = decrypt(user.role);
        const token = jwt.sign(
            { username: user.username, role: decryptedRole },
            JWT_SECRET,
            { expiresIn: '5m' }
        );

        res.send({ token, username: user.username, role: decryptedRole });
    } catch (err) {
        res.status(500).send({ message: 'Internal server error.' });
    }
});

// ── GET USERS ──────────────────
app.get('/users', verifyToken, adminOnly, async (req, res) => {
    try {
        const users = await User.find({}, 'username role');
        const safeUsers = users.map(u => ({
            username: u.username,
            role: DOMPurify.sanitize(decrypt(u.role)) 
        }));
        res.send(safeUsers);
    } catch {
        res.status(500).send({ message: 'Error fetching users' });
    }
});

// ── DELETE USER ──────────────────
app.delete('/users/:username', verifyToken, adminOnly, async (req, res) => {
    try {
        await User.findOneAndDelete({ username: req.params.username });
        res.send({ message: 'User deleted successfully' });
    } catch {
        res.status(500).send({ message: 'Error deleting user' });
    }
});

app.listen(3000, () => console.log('Server running on port 3000'));
