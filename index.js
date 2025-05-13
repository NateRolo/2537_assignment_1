'use strict';
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const path = require('path');
const fs = require('fs');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

const app = express();
const port = process.env.PORT || 3000;

// Set up EJS as the view engine
app.set('view engine', 'ejs');

const saltRounds = 12;
const lengthOfTimeout = 1 * 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

if (!mongodb_host || !mongodb_user || !mongodb_password || !mongodb_database || !mongodb_session_secret || !node_session_secret) {
    console.error("FATAL ERROR: Required environment variables are not set. Please check your .env file.");
    process.exit(1);
}

const mongoUrl = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}`; 
const client = new MongoClient(mongoUrl, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

let db;
const userCollection = 'users';

async function connectToDb() {
    try {
        await client.connect();
        db = client.db(mongodb_database);
        console.log("Successfully connected to MongoDB Atlas!");
    } catch (err) {
        console.error("Failed to connect to MongoDB", err);
        process.exit(1);
    }
}

connectToDb();

/* Session setup */
const mongoStore = MongoStore.create({
    client: client,
    dbName: mongodb_database,
    collectionName: 'sessions',
    crypto: {
        secret: mongodb_session_secret
    },
    ttl: 60 * 60 //session expires in 1 hour (seconds)
});

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: false,
    cookie: {
        maxAge: lengthOfTimeout
    }
}));

/* Middleware */
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

// Middleware to check if user is authenticated
const requireAuth = (req, res, next) => {
    if (!req.session.authenticated) {
        // If not authenticated, redirect to login page
        return res.redirect('/login');
    }
    // If authenticated, proceed to the next middleware or route handler
    next();
};

/* Joi schema */
const signupSchema = Joi.object({
    name: Joi.string().required(),
    email: Joi.string().email().required(),
    password: Joi.string().required()
});

const loginSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
});

/* Routes */
// Home page
app.get('/', (req, res) => {
    res.render('landing.ejs', { 
        authenticated: req.session.authenticated,
        name: req.session.name
    });
});

// Signup page (GET)
app.get('/signup', (req, res) => {
    res.render('signup.ejs', {
        title: 'Sign Up'
    });
});

// Signup page (POST)
app.post('/signup', async (req, res) => {
    const name = req.body.name;
    const email = req.body.email;
    const password = req.body.password;

    // validate input with Joi
    const validationResult = signupSchema.validate({ name, email, password });
    if (validationResult.error) {
        const errorMessage = validationResult.error.details.map(d => d.message).join('<br>');
        return res.status(400).render('signup-fail.ejs', {
            errorMessage: errorMessage,
            showLoginLink: false 
        });
    }

    try {
        // check if user exists
        const existingUser = await db.collection(userCollection).findOne({ email: email });
        if (existingUser) {
            return res.status(409).render('signup-fail.ejs', {
                title: 'Signup Failed',
                errorMessage: 'Email already registered.',
                showLoginLink: true 
            });
        }

        // hash password
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Insert new user with user_type set to 'member'
        const newUser = {
            name: name,
            email: email,
            password: hashedPassword,
            user_type: 'member'  // Set default user type to member
        };
        const result = await db.collection(userCollection).insertOne(newUser);

        req.session.authenticated = true;
        req.session.name = name;
        req.session.email = email;
        req.session.userId = result.insertedId;
        req.session.userType = 'member';  // Store user type in session
        req.session.cookie.maxAge = lengthOfTimeout;

        console.log(`User created: ${name} (${email}) as member`);
        res.redirect('/members'); 

    } catch (error) {
        console.error("signup error: ", error);
        res.status(500).render('error.ejs', {
            title: 'Internal Server Error',
            message: 'Something went wrong during signup. Please try again later.'
        });
    }
});

// Login page (GET)
app.get('/login', async (req, res) => {
    res.render('login.ejs', {
        title: 'Login'
    });
})

// Login page (POST)
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    // Validate input using Joi
    const validationResult = loginSchema.validate({ email, password });
    if (validationResult.error) {
        const errorMessage = validationResult.error.details.map(d => d.message).join('<br>');
        return res.status(400).render('login-fail.ejs', {
            title: 'Login Failed',
            errorMessage: `Invalid input: ${errorMessage}`
        });
    }

    try {
        // Find the user by email
        const user = await db.collection(userCollection).findOne({ email: email });
        if (!user) {
            // Render login-fail view for user not found
            return res.status(401).render('login-fail.ejs', {
                title: 'Login Failed',
                errorMessage: 'Invalid email or password.'
            });
        }

        // Compare the provided password with the stored hash
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            // Render login-fail view for password mismatch
            return res.status(401).render('login-fail.ejs', {
                title: 'Login Failed',
                errorMessage: 'Invalid email or password.'
            });
        }

        // Password is correct, create session
        req.session.authenticated = true;
        req.session.name = user.name;
        req.session.email = user.email;
        req.session.userId = user._id;
        req.session.userType = user.user_type || 'member';  // Store user type in session
        req.session.cookie.maxAge = lengthOfTimeout; 

        console.log(`User logged in: ${user.name} (${user.email}) as ${req.session.userType}`);
        res.redirect('/'); 

    } catch (error) {
        console.error("Login error:", error);
        res.status(500).render('error.ejs', {
            title: 'Internal Server Error',
            message: 'Something went wrong during login. Please try again later.'
        });
    }
});

// Members page
app.get('/members', requireAuth, (req, res) => {
    const imageDir = path.join(__dirname, 'public', 'images');
    const images = [];

    try {
        const files = fs.readdirSync(imageDir);
        const imageFiles = files.filter(file => /\.(gif|jpe?g|png|webp)$/i.test(file));

        if (imageFiles.length > 0) {
            images.push(...imageFiles.map(file => `/images/${file}`));
        } else {
            console.warn("No image files found in", imageDir);
        }
    } catch (err) {
        console.error("Error reading images directory:", err);
    }

    res.render('members', {
        title: 'Members Area',
        name: req.session.name,
        authenticated: req.session.authenticated,
        images: images,
        isAdmin: req.session.userType === 'admin'
    });
});

// Admin middleware
const requireAdmin = async (req, res, next) => {
    if (!req.session.authenticated) {
        return res.redirect('/login');
    }

    try {
        const user = await db.collection(userCollection).findOne({ _id: new ObjectId(String(req.session.userId)) });
        if (!user || user.user_type !== 'admin') {
            return res.status(403).render('error', {
                title: 'Access Denied',
                message: 'You do not have permission to access this page.'
            });
        }
        next();
    } catch (error) {
        console.error("Admin check error:", error);
        res.status(500).render('error', {
            title: 'Server Error',
            message: 'An error occurred while checking admin status.'
        });
    }
};

// Admin page
app.get('/admin', requireAdmin, async (req, res) => {
    try {
        const users = await db.collection(userCollection).find({}).toArray();
        res.render('admin', {
            title: 'Admin Dashboard',
            users: users,
            authenticated: req.session.authenticated,
            name: req.session.name,
            isAdmin: true
        });
    } catch (error) {
        console.error("Admin page error:", error);
        res.status(500).render('error', {
            title: 'Server Error',
            message: 'An error occurred while loading the admin page.'
        });
    }
});

// Promote user to admin
app.post('/admin/promote', requireAdmin, async (req, res) => {
    const userId = req.body.userId;
    
    try {
        await db.collection(userCollection).updateOne(
            { _id: userId },
            { $set: { user_type: 'admin' } }
        );
        res.redirect('/admin');
    } catch (error) {
        console.error("Promote user error:", error);
        res.status(500).render('error', {
            title: 'Server Error',
            message: 'An error occurred while promoting the user.'
        });
    }
});

// Demote admin to user
app.post('/admin/demote', requireAdmin, async (req, res) => {
    const userId = req.body.userId;
    
    try {
        await db.collection(userCollection).updateOne(
            { _id: userId },
            { $set: { user_type: 'user' } }
        );
        res.redirect('/admin');
    } catch (error) {
        console.error("Demote user error:", error);
        res.status(500).render('error', {
            title: 'Server Error',
            message: 'An error occurred while demoting the user.'
        });
    }
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error("Error destroying session:", err);
            return res.status(500).send('Could not log out.');
        }
        // Session destroyed successfully
        console.log('User logged out');
        res.redirect('/'); // Redirect to home page
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).render('404', {
        title: 'Page Not Found',
        authenticated: req.session.authenticated,
        name: req.session.name
    });
});

// --- Start Server ---
app.listen(port, () => {
    console.log(`Server listening on http://localhost:${port}`);
}); 
