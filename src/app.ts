import express from 'express';
import passport from 'passport';
import session from 'express-session';
import dotenv from 'dotenv';
import cors from 'cors';
import './passport';
import path from 'path';

// Used to load environment variables from a .env file into process.env.
// The google client id, client secret as well as the session secret
// are needed for this app.
//GOOGLE_CLIENT_ID=
//GOOGLE_CLIENT_SECRET=
//SESSION_SECRET=

dotenv.config();

// Create an Exprdss app.
const app = express();
// evelopment
const PORT = 3000;

// Middleware configuration is setting up CORS (Cross-Origin Resource Sharing) 
// for the Express application.

// Must set credentials to true for cookies to be send
// and authentication to work properly.
app.use(cors({
  origin: 'http://localhost:${PORT}',  // Frontend URL
  credentials: true,                   // Allow credentials (cookies) to be sent  
}));

// We need to establish a session so that we have a mechanism
// to store an authentication cookie within a session.

app.use(
  session({
    secret: process.env.SESSION_SECRET!,
    // Setting resave to false helps prevent the server from storing 
    // sessions that aren't being used
    resave: false,
    // This setting ensures that sessions that are not modified will not be saved
    // This can be useful for saving resources, as the session store will not be 
    // unnecessarily populated with empty or default sessions
    saveUninitialized: false,
    // Session cookie along with an expiration time
    cookie: {
      secure: false,  // Set to true if using HTTPS
      httpOnly: true,
      sameSite: true, // Use 'none' if using cross-origin requests with HTTPS
      maxAge: 20 * 60 * 1000, // 20 minutes in milliseconds in this format for readability    
    }
  })
);

// Passport is required to initialize Passport in your application so that it can handle 
// authentication-related tasks, such as managing user sessions, handling login requests, 
// and managing serialized user data.
app.use(passport.initialize());

// Integrates Passport with Express's session management and makes sure that user 
// authentication is persisted across requests by maintaining the user's session.
app.use(passport.session());

// The isAuthenticated function is a custom middleware used in your Express app to protect 
// certain routes, ensuring that only authenticated users can access them
// /api/protected herein calls isAuthenticated to verify that the user is authenticated
// beford proceeding.  It is important to understand that this would not be necessary
// if all routes require authentication.  The parameter passed from /api/protected would
// be omitted in that scenario and the way you implement all routes is to use 
// app.use(isAuthenticated); as the last statement in this app.ts file.  It is the
// last statement, therefore the isAuthenticated code isn't necessary and the
// /api/protected isAuthenticated parameter is ignored.  If the last line of code
// didn't exist this would be the fallback.
const isAuthenticated = (req: express.Request, res: express.Response, 
  next: express.NextFunction) => {
  if (req.isAuthenticated()) {
      console.log("isauthenticated: ", req.isAuthenticated())
      return next();
  }
  res.status(401).json({ message: 'Unauthorized' });
};  

// This route is triggered when a user accesses the URL /auth/google (for example, by 
// clicking the googleAuthButton on the index.html page of this app.
// It will bring up the google login page.
app.get('/auth/google', (req, res, next) => {

  next();
}, passport.authenticate('google', { scope: ['profile', 'email'],  accessType: 'offline',   prompt: 'select_account' }));
 
// This code is called from the index.html for logging out.
// The logoutButton click event fires this route which in turn destroys the session
// and clears the session cookie.  After this route executes, the app is rendered
// non-functional.  It exists for the sole purpose of destroying the session and
// cookie for test purposes.

app.post('/auth/logout', (req, res, next) => {
  next();

  req.logout((err: any) => {  // err can be of type any since it's passed to the callback
    if (err) {
      return res.status(500).json({ message: 'Logout failed' });
    }

    // Destroy the session on the server side
     req.session?.destroy((err: Error | null) => {  // Use optional chaining in case `req.session` is undefined
      if (err) {
        return res.status(500).json({ message: 'Session destruction failed' });
      }
    console.log('Session after destruction:', req.session);

      // Explicitly clear the session cookie from the client's browser
       res.clearCookie('connect.sid', {}); 
    });
  });
});


// used isAuthenticated to protect individual routes unless
// all routes are protected.  Using app.use(isAuthenticated); 
// as the last call forces all routes to require authentication
// so this is just an example of how to enforce it on a route 
// by route basis if you didn't want it enforced for all routes.
app.get('/api/protected',  isAuthenticated,  (req, res) => {
  console.log("Session Cookie MaxAge after authentication:", req.session.cookie); 
  
  res.json({ message: 'You have access!' });
});

// This code defines an Express route handler for the callback URL /auth/google/callback, 
// which is the URL Google will redirect to after a user has authenticated with their Google account. 

// Flow of Execution:
// User Authentication with Google:

// The user navigates to /auth/google (as shown in the previous route).
// After successful authentication and authorization via Google, the user is redirected to /auth/google/callback.
// Google Callback Handling:

// The /auth/google/callback route is triggered.
// passport.authenticate('google') verifies the authentication response from Google.
// If authentication succeeds, it proceeds to the next middleware (the callback function).
// Session and User Logging:

// The callback function logs the session cookie (maxAge), 
// whether the user is authenticated, and the user object.
// The user is then redirected to the home page (/).
app.get(
  '/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    console.log("Session Cookie MaxAge after authentication:", req.session.cookie); // Log maxAge
    console.log("isauthenticated = ", req.isAuthenticated());
    console.log('Authenticated user:', req.user);
    // Redirect the user to home page or other page after successful login
    res.redirect('/');
  }
);

// Serve the index.html page when accessing the root URL
app.get('/', (req, res) => {
  //console.log('about to send index.html');
  res.sendFile(path.join(__dirname, '../public', 'index.html'));  // Go up one directory to reach the public folder

});

// This code defines a route handler for the URL /auth/status, 
// which is typically used to check the authentication status of the user. 

 app.get('/auth/status', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');  // Disable caching for this route

  if (req.isAuthenticated()) {
      res.json({ authenticated: true, user: req.user });
  } else {
      res.json({ authenticated: false });
  }
});

// Using app.use(isAuthenticated); will enforce authentication on all routes that come 
// after this middleware in your Express app. 
// Here's what happens when you apply this globally:

// All requests will be checked for authentication before reaching their intended route handlers.
// If a user is authenticated (req.isAuthenticated() returns true), the request proceeds 
// to the next middleware or route handler.

//If a user is not authenticated, they receive a 401 Unauthorized response.

app.use(isAuthenticated); // Apply to all routes

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

