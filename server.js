// server.js
const express = require("express");
const rateLimit = require("express-rate-limit");
const Joi = require("joi");
const admin = require('firebase-admin');

const allowedCommands = require("./allowedCommands");
const app = express();

// Middleware to parse JSON bodies in incoming requests
app.use(express.json());

// Initialize Firebase Admin SDK
const serviceAccount = process.env.FIRESTORE || require('./telemetry-data-hedera-firebase-adminsdk.json');

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});
const db = admin.firestore();

// In-memory objects to track violations and bans
const violationTracker = {};
const bannedIPs = {};

// Middleware to check if an IP is banned
function banMiddleware(req, res, next) {
  const ip = req.ip;
  if (bannedIPs[ip] && bannedIPs[ip].banned) {
    return res.status(403).json({ error: 'Your IP has been banned.' });
  }
  next();
}

const telemetryLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute window
  max: 1, // limit to 1 invalid requests per minute
  standardHeaders: "draft-8", // draft-6: `RateLimit-*` headers; draft-7 & draft-8: combined `RateLimit` header
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers.
  message: { error: "Too many telemetry requests, please try again later." },
  handler: (req, res, next, options) => {
    const ip = req.ip;
    // Increment the violation counter for this IP
    violationTracker[ip] = (violationTracker[ip] || 0) + 1;
    console.log(`IP ${ip} exceeded rate limit ${violationTracker[ip]} times.`);

    // Ban the IP if it has violated the limit 10 times consecutively
    if (violationTracker[ip] >= 10) {
      bannedIPs[ip] = { banned: true, bannedAt: Date.now() };
      console.log(`IP ${ip} has been banned at ${Date.now()}.`);
    }

    res.status(options.statusCode).json({ error: options.message });
  },
  skipSuccessfulRequests: true, // only counts for invalid requests
});

// Apply the rate limiting middleware to all requests.
app.use(telemetryLimiter);
app.use(banMiddleware); // Apply ban check to all requests

// Regular expression to validate UUID format.
const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Middleware to validate and extract the installation token.
 */
app.use((req, res, next) => {
  // Extract token from the custom header (case-insensitive)
  const token = req.headers['x-telemetry-token'];
  if (!token) {
    return res.status(400).json({ error: 'Missing installation token' });
  }
  if (!uuidRegex.test(token)) {
    return res.status(400).json({ error: 'Invalid installation token format' });
  }
  // Attach token to the request for later use
  req.uuid = token;
  next();
});


// Define a Joi schema for telemetry data
const telemetrySchema = Joi.object({
  command: Joi.string().valid(...allowedCommands).required(),
  timestamp: Joi.string().isoDate().required(),
  // 'version' must be a string in the format X.Y.Z, for example "0.2.0" or "1.1.0".
  version: Joi.string()
    .pattern(/^\d+\.\d+\.\d+$/)
    .required(),
});

// Define the /track endpoint to accept POST requests
app.post("/track", async (req, res) => {
  // Validate the incoming request body against the schema
  const { error, value } = telemetrySchema.validate(req.body);
  
  if (error) {
    // Return a 400 error if validation fails
    console.error(`Invalid request for UUID: ${req.uuid} - At: ${new Date().toISOString()}`);
    return res.status(400).json({ error: error.details[0].message });
  }

  // Assuming the telemetry payload includes a command and a timestamp
  const { command, timestamp, version } = value;

  // Log the telemetry to the console
  console.log(
    `Command: ${command.trim().toLowerCase()} -> received at: ${timestamp} --> v${version} ---> UUID: ${req.uuid}`
  );

  try {
    // Add a new document to the "telemetry" collection
    await db.collection('telemetry').add({
        command: command.trim().toLowerCase(),
        timestamp,
        version,
        uuid: req.uuid,
    });
    res.status(200).json({ message: 'Telemetry data stored successfully' });
  } catch (err) {
    console.error('Error writing to Firestore:', err);
    res.status(500).json({ error: 'Failed to store telemetry data' });
  }
});

// Start the server on port 3001 or the port specified in the environment variables
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Telemetry server listening on port ${PORT}`);
});

app.keepAliveTimeout = 120 * 1000;
app.headersTimeout = 120 * 1000;
