/** @format */

import express, { Request, Response } from "express";
import { Pool } from "pg";
import nodemailer from "nodemailer";
import crypto from "crypto";
import dotenv from "dotenv";

// Load environment variables
dotenv.config();

const app = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

app.use(express.json()); // Middleware to parse JSON requests

// Setup SMTP Transporter using Nodemailer
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: false, // Use true for 465, false for other ports like 587
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// Utility function to generate a 6-digit OTP
const generateOTP = (): string => {
  return crypto.randomInt(100000, 999999).toString();
};

// Send OTP Route
app.post("/send-otp", async (req: Request, res: Response) => {
  const { email } = req.body;

  try {
    // Check if the user is already registered and verified
    const user = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    if (user.rows.length > 0 && user.rows[0].is_verified) {
      return res
        .status(400)
        .json({ message: "User already registered and verified." });
    }

    // Generate OTP and expiration time
    const otp = generateOTP();
    const otpExpiration = new Date(
      Date.now() + +process.env.OTP_EXPIRY_MINUTES! * 60000
    );

    // Upsert OTP and expiration into the users table
    await pool.query(
      `INSERT INTO users (email, otp, otp_expiration) 
       VALUES ($1, $2, $3) 
       ON CONFLICT (email) DO UPDATE 
       SET otp = $2, otp_expiration = $3`,
      [email, otp, otpExpiration]
    );

    // Send OTP via email using SMTP
    await transporter.sendMail({
      from: `"House of Gifts" <${process.env.SMTP_USER}>`, // Sender address
      to: email,
      subject: "Your OTP for Registration",
      text: `Your OTP is ${otp}. It will expire in ${process.env.OTP_EXPIRY_MINUTES} minutes.`,
    });

    res.status(200).json({ message: "OTP sent successfully." });
  } catch (error) {
    console.error("Error sending OTP:", error);
    res.status(500).json({ message: "Error sending OTP." });
  }
});

// Verify OTP Route
app.post("/verify-otp", async (req: Request, res: Response) => {
  const { email, otp } = req.body;

  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    const user = result.rows[0];

    if (!user) return res.status(404).json({ message: "User not found." });

    if (user.otp !== otp)
      return res.status(400).json({ message: "Invalid OTP." });

    if (new Date() > user.otp_expiration) {
      return res.status(400).json({ message: "OTP expired." });
    }

    // Mark user as verified
    await pool.query("UPDATE users SET is_verified = true WHERE email = $1", [
      email,
    ]);

    res.status(200).json({ message: "OTP verified successfully." });
  } catch (error) {
    console.error("Error verifying OTP:", error);
    res.status(500).json({ message: "Error verifying OTP." });
  }
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
