import passport from 'passport';
import { Strategy as GoogleStrategy, VerifyCallback } from 'passport-google-oauth20';
import dotenv from 'dotenv';

// Load environment variables from .env file
// The environment variables are for the client id
// and secret of the google authentication provider.
// This will be you.  
// Follow the url below to configure your app for
// Google authentication

// https://console.cloud.google.com/auth

dotenv.config();

// Verify the data are populated from the configuration file .env

//console.log('GOOGLE_CLIENT_ID:', process.env.GOOGLE_CLIENT_ID);
//console.log('GOOGLE_CLIENT_SECRET:', process.env.GOOGLE_CLIENT_SECRET);  
//console.log('SESSION_SECRET:', process.env.SESSION_SECRET);  

// Configure Google OAuth strategy
// 
interface GoogleStrategyOptions {
  clientID: string;
  clientSecret: string;
  callbackURL: string;
  scope: string[];
}

// Google OAuth returns user profile data in a generic format, and the 
// structure can vary slightly depending on the OAuth provider's implementation 
// or any changes on the provider's side. The data that Google provides 
// can also depend on the specific scope of the request 
// (e.g., profile, email, etc.).

// You, the developer defines the UserProfile interface to match the data you 
// expect based on the scope of the Google OAuth request and how you want 
// to use that data in your application.

// I am including more information than what might be needed for
// clarity on what additional data is here that you may or may not want.

// When I instantiate a new GoogleStrategy herein, I will give it a scope
// of profile and email, therefore these values will be populated
// into my interface structure definition. 
// scope: ["profile", "email"],


interface UserProfile {
  id: string;
  displayName: string;
  name?: {
    familyName: string;
    givenName: string;
  };
  emails?: Array<{
    value: string;
    type?: string;
  }>;
  photos?: Array<{
    value: string;
  }>;
}

// We are authenticating using Google, so use the Google Strategy
// Implementation of a Strategy Pattern.  This is a really good
// example of the strategy pattern and it's usefulness.
// Different strategies such as Good, Twitter, Faceboo, etc.
// can be implemented separately without breaking the passport
// core functionality.

// First, register a strategy.  In this case, Google

// The GoogleStrategy is being passed as a parameter to this method, meaning 
// Passport will use Google’s OAuth2 service to authenticate users.


passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      
      // The callbackURL is the URL where Google will redirect users after they authenticate, 
      // once the OAuth flow is completed.

      // In this case, it's set to "/auth/google/callback", meaning after the user has authenticated 
      // with Google, they will be redirected to the /auth/google/callback route on your server 
      // for handling the response.
      
      // This URL must match the one you set in your Google Developer Console when configuring 
      // your OAuth client ID and secret.

      // See the app.ts for the definition of this route.
      callbackURL: "/auth/google/callback",
      scope: ["profile", "email"],

    },
      (accessToken: string, refreshToken: string, userProfile: UserProfile, done: VerifyCallback) => {
        
        // (accessToken: string, refreshToken: string, profile: Profile, done: VerifyCallback) => {
        // console.log("Access Token:", accessToken); 
        // console.log("Refresh Token:", refreshToken);

        // If authentication failed then call done with an error and false for success flag.
        if (!userProfile) {
          console.log("User Profile:", userProfile); 
          return done(new Error("User profile not found"), false); 
        }

        // The done callback function is used to indicate the outcome of the authentication attempt. 
        // It essentially ends the authentication flow and passes the result back to Passport.

        // By calling done(null, userProfile), you are telling Passport that the authentication was 
        // successful, and the user’s profile (userProfile) should be saved in the session.

        return done(null, userProfile);
    }
  )
)

// Serialize the user object to store it in the session
// SerializeUser is used to determine what data will be stored in the session. 
// Here, the entire userProfile object is being stored in the session. 
// Typically, you would store just a user ID or key

passport.serializeUser((userProfile, done) => {
  done(null, userProfile);
});

// DeserializeUser is used to retrieve the user object from the session. 
// When a user makes a request, the session contains a reference to the 
// user (serialized previously). deserializeUser is responsible for loading 
// the user object from the session data.

//Here, the userProfile object is being cast to Express.User, which may be a 
// custom type if you're using TypeScript and need to match the structure of 
// your user model. This allows you to access the user data in your routes, 
// after deserialization.

passport.deserializeUser((userProfile, done) => {
  done(null, userProfile as Express.User); // Make sure to type it correctly if needed
});

