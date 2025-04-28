'use strict';
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

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

const { MongoClient, ServerApiVersion } = require('mongodb');
const mongoUrl = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}`; // Construct connection string
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
        // Exit if DB connection fails
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
        maxAge: 1000 * 60 * 60 // Cookie expiry matches session TTL (1 hour in milliseconds)
    }
}));

/* Middleware */
app.use(express.urlencoded({ extended: false })); 
app.use(express.static(path.join(__dirname, 'public'))); 

/* Joi schema */
const signupSchema = Joi.object({
    username: Joi.string().required(),
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
    res.send(`
        <h1>Home Page</h1>
        ${req.session.authenticated ?
            `<p>Hello, ${req.session.username}</p>
             <a href="/members">Members Area</a><br>
             <a href="/logout">Logout</a>` :
            `<a href="/signup">Sign Up</a><br>
             <a href="/login">Login</a>`
        }
    `);
});

// Signup page (GET)
app.get('/signup', (req, res) => {
    res.send(`
        <h1>Sign Up</h1>
        <form action="/signup" method="post">
            <input name="username" type="text" placeholder="Username" required><br>
            <input name="email" type="email" placeholder="Email" required><br>
            <input name="password" type="password" placeholder="Password" required><br>
            <button type="submit">Sign Up</button>
        </form>
        <p>Already have an account? <a href="/login">Log In</a></p>
    `);
});

// Signup page (POST)
app.post('/signup', async (req, res) => {
    const username = req.body.username;
    const email = req.body.email;
    const password = req.body.password;

    // validate input with Joi
    const validationResult = signupSchema.validate({ username, email, password });
    if(validationResult.error) {
        const errorMessage = validationResult.error.details.map(d => d.message).join('<br>');
        return res.status(400).send(`
            <h1>Signup Failed</h1>
            <p>Invalid input: ${errorMessage}</p>
            <a href="/signup">Try again</a>`
        );
    }

    try {
        // check if user exists
        const existingUser = await db.collection(userCollection).findOne({email:email});
        if(existingUser) {
            return res.status(409).send(`
                <h1>Signup Failed</h1>
                <p>Email already registered.</p>
                <a href="/signup">Try again</a> or <a href="/login">Login</a>`
            );
        }

        // hash password
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Insert new user
        const newUser = {
            username: username,
            email: email,
            password: hashedPassword
        };
        const result = await db.collection(userCollection).insertOne(newUser);

        req.session.authenticated = true;
        req.session.username = username;
        req.session.email = email;
        req.session.userId = result.insertedId; 
        req.session.cookie.maxAge = lengthOfTimeout;

        console.log(`User created: ${username} (${email})`);
        res.redirect('/members');

    } catch(error) {
        console.error("signup error: ", error);
         res.status(500).send('<h1>Internal Server Error</h1><p>Something went wrong during signup. Please try again later.</p>');
    }
});

// Login page (POST)
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    // Validate input using Joi
    const validationResult = loginSchema.validate({ email, password });
    if (validationResult.error) {
        const errorMessage = validationResult.error.details.map(d => d.message).join('<br>');
        return res.status(400).send(`
            <h1>Login Failed</h1>
            <p>Invalid input: ${errorMessage}</p>
            <a href="/login">Try again</a>
        `);
    }

    try {
        // Find the user by email
        const user = await db.collection(userCollection).findOne({ email: email });
        if (!user) {
            // User not found
            return res.status(401).send(`
                <h1>Login Failed</h1>
                <p>Invalid email or password.</p> 
                <a href="/login">Try again</a>
            `); 
        }

        // Compare the provided password with the stored hash
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            // Passwords don't match
            return res.status(401).send(`
                <h1>Login Failed</h1>
                <p>Invalid email or password.</p> 
                <a href="/login">Try again</a>
            `); 
        }

        // Password is correct, create session
        req.session.authenticated = true;
        req.session.username = user.username; 
        req.session.email = user.email;
        req.session.userId = user._id; 
        req.session.cookie.maxAge = lengthOfTimeout; // Reset cookie timeout

        console.log(`User logged in: ${user.username} (${user.email})`);
        res.redirect('/members'); // Redirect to members area

    } catch (error) {
        console.error("Login error:", error);
        res.status(500).send('<h1>Internal Server Error</h1><p>Something went wrong during login. Please try again later.</p>');
    }
});

// Members page
app.get('/members', (req, res) => {
    // Placeholder: Check session, display content or redirect
    res.send('Members Area - To be implemented');
});

// Logout
app.get('/logout', (req, res) => {
    // Placeholder: Destroy session, redirect
    res.send('Logout route - To be implemented');
});

// 404 Handler (Must be the last route)
app.use((req, res) => {
    res.status(404).send("404: Page not found");
});

// --- Start Server ---
app.listen(port, () => {
    console.log(`Server listening on http://localhost:${port}`);
}); 
