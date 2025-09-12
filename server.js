"use strict";

/**
 * Main server file with security hardening implementations.
 * Week 4 Security Features:
 * - Intrusion Detection & Monitoring (fail2ban configuration, IP blocking, logging)
 * - API Security Hardening (rate limiting, CORS, JWT authentication)
 * - Security Headers & CSP (helmet, content security policy, HSTS)
 */

const express = require("express");
const favicon = require("serve-favicon");
const bodyParser = require("body-parser");
const session = require("express-session");
// const csrf = require('csurf');
const consolidate = require("consolidate"); // Templating library adapter for Express
const swig = require("swig");
const helmet = require("helmet");
const MongoClient = require("mongodb").MongoClient; // Driver for connecting to MongoDB
const http = require("http");
const marked = require("marked");
const nosniff = require('dont-sniff-mimetype');
const rateLimit = require('express-rate-limit'); // Rate limiting middleware
const cors = require('cors'); // CORS middleware
const jwt = require('jsonwebtoken'); // JWT for API authentication
const fs = require("fs");
const https = require("https");
const path = require("path");
const morgan = require('morgan'); // HTTP request logger
const app = express(); // Web framework to handle routing requests
const routes = require("./app/routes");
const { port, db, cookieSecret } = require("./config/config"); // Application config properties

// Fix for A6-Sensitive Data Exposure
// Load keys for establishing secure HTTPS connection
const httpsOptions = {
    key: fs.readFileSync(path.resolve(__dirname, "./artifacts/cert/server.key")),
    cert: fs.readFileSync(path.resolve(__dirname, "./artifacts/cert/server.crt"))
};

// Load environment variables for security features
require('dotenv').config();

// Configure Winston logger for security monitoring
const winston = require('winston');

// Create a custom format for detailed security logging
const securityFormat = winston.format.combine(
    winston.format.timestamp(),
    winston.format.json(),
    winston.format.printf(info => {
        if (info.meta && info.meta.req) {
            return `${info.timestamp} ${info.level}: ${info.message} - IP: ${info.meta.req.ip}, User-Agent: ${info.meta.req.headers['user-agent']}`;
        }
        return `${info.timestamp} ${info.level}: ${info.message}`;
    })
);

// Configure logger with multiple transports
const logger = winston.createLogger({
    format: securityFormat,
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'logs/security.log' }),
        new winston.transports.File({ filename: 'logs/failed-logins.log', level: 'warn' })
    ]
});

// Track login attempts for intrusion detection
const loginAttempts = {}; // Simple in-memory store for tracking login attempts
const MAX_LOGIN_ATTEMPTS = process.env.MAX_LOGIN_ATTEMPTS || 5;
const BLOCK_TIME_MS = process.env.BLOCK_TIME_MS || 3600000; // 1 hour by default

// Simple IP blocking mechanism (alternative to fail2ban)
const ipBlocklist = new Map();

logger.info('Application started with enhanced security features');

/**
 * Middleware for IP-based intrusion detection
 * Blocks IP addresses with too many failed login attempts
 */
const ipBlockMiddleware = (req, res, next) => {
    const clientIP = req.ip || req.connection.remoteAddress;
    
    // Check if the IP is in the blocklist
    if (ipBlocklist.has(clientIP)) {
        const blockData = ipBlocklist.get(clientIP);
        if (Date.now() < blockData.expiry) {
            logger.warn(`Blocked request from banned IP: ${clientIP}`, { meta: { req } });
            return res.status(403).json({ error: 'Too many failed attempts. Please try again later.' });
        } else {
            // If block has expired, remove from blocklist
            ipBlocklist.delete(clientIP);
        }
    }
    next();
};

/**
 * API Key Authentication Middleware
 * Verifies API keys for selected routes
 */
const apiKeyAuth = (req, res, next) => {
    const apiKey = req.header('X-API-KEY');
    const validApiKey = process.env.API_KEY || 'default-dev-api-key';
    
    if (!apiKey || apiKey !== validApiKey) {
        logger.warn(`Unauthorized API access attempt`, { meta: { req } });
        return res.status(401).json({ error: 'Invalid API key' });
    }
    next();
};

/**
 * JWT Authentication Middleware
 * Verifies JWT tokens for protected routes
 */
const jwtAuth = (req, res, next) => {
    const authHeader = req.header('Authorization');
    const token = authHeader ? authHeader.split(' ')[1] : null; // Extract token from Bearer header
    
    if (!token) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    try {
        const jwtSecret = process.env.JWT_SECRET || 'default-dev-jwt-secret';
        const decoded = jwt.verify(token, jwtSecret);
        req.user = decoded;
        next();
    } catch (error) {
        logger.warn(`Invalid JWT token`, { meta: { req, error: error.message } });
        res.status(400).json({ error: 'Invalid token.' });
    }
};

MongoClient.connect(db, (err, db) => {
    if (err) {
        logger.error("Error: DB: connect");
        logger.error(err);
        process.exit(1);
    }
    logger.info(`Connected to the database`);

    // Morgan logger for HTTP request logging
    const logFormat = ':remote-addr - :remote-user [:date[clf]] ":method :url HTTP/:http-version" :status :res[content-length] ":referrer" ":user-agent"';
    app.use(morgan(logFormat, {
        stream: {
            write: (message) => logger.info(message.trim())
        }
    }));
    
    // Apply IP blocking middleware to all requests
    app.use(ipBlockMiddleware);
    
    // Apply rate limiting to all requests
    const limiter = rateLimit({
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: process.env.RATE_LIMIT_MAX || 100, // limit each IP to 100 requests per windowMs
        message: 'Too many requests from this IP, please try again later',
        standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
        legacyHeaders: false, // Disable the `X-RateLimit-*` headers
        handler: (req, res) => {
            logger.warn(`Rate limit exceeded for IP: ${req.ip}`, { meta: { req } });
            res.status(429).json({ error: 'Too many requests, please try again later' });
        }
    });
    app.use(limiter);
    
    // Configure CORS to allow only specific origins
    const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://localhost:4000').split(',');
    app.use(cors({
        origin: function(origin, callback) {
            // Allow requests with no origin (like mobile apps or curl requests)
            if (!origin) return callback(null, true);
            
            if (allowedOrigins.indexOf(origin) === -1) {
                logger.warn(`CORS blocked request from origin: ${origin}`);
                return callback(new Error('CORS policy: Not allowed by CORS'), false);
            }
            return callback(null, true);
        },
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization', 'X-API-KEY'],
        credentials: true, // Allow cookies
        maxAge: 86400 // Cache preflight response for 24 hours
    }));

    // Configure Helmet with enhanced security settings
    app.use(helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'", "'unsafe-inline'"], // Consider removing unsafe-inline in production
                styleSrc: ["'self'", "'unsafe-inline'"],
                imgSrc: ["'self'", 'data:'],
                connectSrc: ["'self'"],
                fontSrc: ["'self'"],
                objectSrc: ["'none'"],
                mediaSrc: ["'self'"],
                frameSrc: ["'none'"],
                upgradeInsecureRequests: []
            }
        },
        hsts: {
            maxAge: 31536000, // 1 year in seconds
            includeSubDomains: true,
            preload: true
        },
        frameguard: { 
            action: 'deny' 
        },
        xssFilter: true,
        noSniff: true,
        referrerPolicy: { policy: 'same-origin' }
    }));

    // Remove default x-powered-by response header
    app.disable("x-powered-by");
    
    // Forces browser to only use the Content-Type set in the response header instead of sniffing
    app.use(nosniff());
    
    // Adding/remove HTTP Headers for security
    app.use(favicon(__dirname + "/app/assets/favicon.ico"));

    // Express middleware to populate "req.body" so we can access POST variables
    app.use(bodyParser.json());
    app.use(bodyParser.urlencoded({
        // Mandatory in Express v4
        extended: false
    }));

    // Enable session management using express middleware
    app.use(session({
        // genid: (req) => {
        //    return genuuid() // use UUIDs for session IDs
        //},
        secret: cookieSecret,
        // Both mandatory in Express v4
        saveUninitialized: true,
        resave: true
        /*
        // Fix for A5 - Security MisConfig
        // Use generic cookie name
        key: "sessionId",
        */

        /*
        // Fix for A3 - XSS
        // TODO: Add "maxAge"
        cookie: {
            httpOnly: true
            // Remember to start an HTTPS server to get this working
            // secure: true
        }
        */

    }));

    // Enable Express csrf protection using our enhanced middleware
    const csrfMiddleware = require('./middleware/csurf-init');
    app.use(csrfMiddleware);

    // Register templating engine
    app.engine(".html", consolidate.swig);
    app.set("view engine", "html");
    app.set("views", `${__dirname}/app/views`);
    
    // Fix for A5 - Security MisConfig
    // TODO: make sure assets are declared before app.use(session())
    app.use(express.static(`${__dirname}/app/assets`));

    // Initializing marked library
    // Fix for A9 - Insecure Dependencies
    marked.setOptions({
        sanitize: true
    });
    app.locals.marked = marked;
    
    // Track failed login attempts and implement IP blocking
    app.post('/login', async (req, res, next) => {
        const clientIP = req.ip || req.connection.remoteAddress;
        const username = req.body.username;
        
        // Initialize tracking for this IP if it doesn't exist
        if (!loginAttempts[clientIP]) {
            loginAttempts[clientIP] = {
                count: 0,
                lastAttempt: Date.now(),
                username: username
            };
        }
        
        // Track this attempt
        loginAttempts[clientIP].count++;
        loginAttempts[clientIP].lastAttempt = Date.now();
        loginAttempts[clientIP].username = username;
        
        // Check if this IP should be blocked
        if (loginAttempts[clientIP].count >= MAX_LOGIN_ATTEMPTS) {
            // Add to blocklist
            ipBlocklist.set(clientIP, {
                expiry: Date.now() + BLOCK_TIME_MS,
                reason: 'Too many failed login attempts'
            });
            
            // Log the blocking event
            logger.warn(`IP ${clientIP} blocked due to excessive login failures for user: ${username}`, { 
                meta: { req, attempts: loginAttempts[clientIP].count }
            });
            
            // Reset the counter
            delete loginAttempts[clientIP];
            
            return res.status(403).json({ error: 'Account temporarily locked due to too many failed login attempts.' });
        }
        
        // Continue with regular login process
        next();
    });

    // Expose API endpoints with authentication
    app.use('/api', apiKeyAuth); // Protect all /api routes with API key auth
    
    // Example JWT protected route
    app.use('/api/secure', jwtAuth); // Protect routes with JWT auth
    
    // Example endpoint to generate JWT token (for testing purposes)
    app.post('/api/auth/token', (req, res) => {
        // In production, validate credentials before generating token
        const jwtSecret = process.env.JWT_SECRET || 'default-dev-jwt-secret';
        const token = jwt.sign({ userId: req.body.userId || 'test-user' }, jwtSecret, { expiresIn: '1h' });
        res.json({ token });
    });

    // Application routes
    routes(app, db);

    // Template system setup
    swig.setDefaults({
        // Fix for A3 - XSS, enable auto escaping
        autoescape: true
    });

    // Use secure HTTPS protocol in production or if FORCE_HTTPS env is set
    const useHttps = process.env.NODE_ENV === 'production' || process.env.FORCE_HTTPS === 'true';
    
    if (useHttps) {
        // Secure HTTPS connection
        https.createServer(httpsOptions, app).listen(port, () => {
            logger.info(`Express https server listening on port ${port}`);
        });
        
        // Redirect HTTP to HTTPS
        http.createServer((req, res) => {
            res.writeHead(301, { 'Location': `https://${req.headers.host}${req.url}` });
            res.end();
        }).listen(process.env.HTTP_PORT || 8080, () => {
            logger.info(`HTTP to HTTPS redirect server running on port ${process.env.HTTP_PORT || 8080}`);
        });
    } else {
        // Insecure HTTP connection - for development only
        http.createServer(app).listen(port, () => {
            logger.info(`Express http server listening on port ${port} (development mode)`);
        });
    }



});
