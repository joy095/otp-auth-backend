/** @format */

// Custom configuration
export const corsOptions = {
  origin: [process.env.WEB_URL],
  methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true, // Allow cookies and credentials
  //maxAge: 86400, // Cache preflight request results for 24 hours
  optionsSuccessStatus: 200,
};
