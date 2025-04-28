'use strict';
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const path = require('path');

const app = express();
const port = provess.env.PORT || 3000;

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

