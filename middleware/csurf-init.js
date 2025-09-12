/**
 * csurf-init.js
 * 
 * This middleware configures CSRF protection for the NodeGoat application.
 * It uses the csurf package to generate and validate CSRF tokens.
 */

const csrf = require('csurf');
const cookieParser = require('cookie-parser');

/**
 * Configure CSRF protection middleware
 * @param {Object} options - Optional configuration options
 * @returns {Function} - Express middleware function
 */
function configureCsrf(options = {}) {
    // Default configuration
    const config = {
        cookie: {
            key: '_csrf-token',
            secure: process.env.NODE_ENV === 'production',
            httpOnly: true,
            sameSite: 'lax'
        },
        value: defaultCsrfValue,
        ...options
    };
    
    // Create the CSRF protection middleware
    const csrfProtection = csrf(config);
    
    // Return a middleware function that handles CSRF setup
    return function csrfMiddleware(req, res, next) {
        // Ensure cookie-parser is applied first
        cookieParser()(req, res, () => {
            // Skip CSRF for GET, HEAD, OPTIONS requests (safe methods)
            if (['GET', 'HEAD', 'OPTIONS'].indexOf(req.method) !== -1) {
                // Still generate the token for templates but don't validate
                csrfProtection(req, res, () => {
                    // Make the CSRF token available to templates
                    setTokenForTemplates(req, res);
                    next();
                });
                return;
            }
            
            // Skip CSRF for API routes using token authentication
            if (isApiRouteWithTokenAuth(req)) {
                return next();
            }
            
            // Apply CSRF protection for all other routes
            csrfProtection(req, res, (err) => {
                if (err) {
                    // Handle CSRF errors
                    handleCsrfError(err, req, res, next);
                    return;
                }
                
                // Make the CSRF token available to templates
                setTokenForTemplates(req, res);
                next();
            });
        });
    };
}

/**
 * Default CSRF token extractor function
 * Checks multiple locations for the CSRF token
 */
function defaultCsrfValue(req) {
    // Check the request body
    let token = (req.body && req.body._csrf) || 
                (req.body && req.body['csrf-token']) || 
                (req.body && req.body.csrfToken);
    
    // Check the request query
    if (!token) {
        token = (req.query && req.query._csrf) || 
                (req.query && req.query['csrf-token']) || 
                (req.query && req.query.csrfToken);
    }
    
    // Check headers (used by AJAX requests)
    if (!token) {
        token = req.headers['csrf-token'] || 
                req.headers['x-csrf-token'] || 
                req.headers['x-xsrf-token'];
    }
    
    return token;
}

/**
 * Check if the request is an API route using token authentication
 */
function isApiRouteWithTokenAuth(req) {
    // Skip CSRF for API routes using JWT or API key authentication
    return (
        // Check if it's an API route
        (req.path.indexOf('/api/') === 0) && 
        // Check for API authentication
        (
            // JWT token in Authorization header
            req.headers['authorization'] || 
            // API key in custom header
            req.headers['x-api-key'] ||
            // Or any other API authentication method you're using
            (req.query && req.query.apiKey)
        )
    );
}

/**
 * Make CSRF token available to templates
 */
function setTokenForTemplates(req, res) {
    if (req.csrfToken) {
        // Create a local variable for templates
        res.locals.csrfToken = req.csrfToken();
    }
}

/**
 * Handle CSRF validation errors
 */
function handleCsrfError(err, req, res, next) {
    if (err.code === 'EBADCSRFTOKEN') {
        // Log the error for security monitoring
        console.error('CSRF attack detected!', {
            url: req.originalUrl,
            ip: req.ip,
            headers: req.headers,
        });
        
        // Return a user-friendly error response
        if (req.xhr || (req.headers.accept && req.headers.accept.indexOf('json') !== -1)) {
            // For AJAX/API requests
            return res.status(403).json({
                error: 'Security validation failed. Please refresh the page and try again.'
            });
        } else {
            // For regular form submissions
            return res.status(403).render('error', {
                error: 'Security validation failed. This may happen if you\'ve been inactive for too long or if you submitted an outdated form. Please refresh the page and try again.'
            });
        }
    }
    
    // Pass other errors to the next middleware
    next(err);
}

module.exports = configureCsrf();
