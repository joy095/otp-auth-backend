/** @format */
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { Request, Response } from "express"; // Types for Express requests and responses

import transporter from "../config/mail";
import { User } from "../types/user";
import pool from "../config/db";
import { deleteOldToken } from "../middlewares/authMiddleware";

// Type definition for environment variables
const SALT_ROUNDS = parseInt(process.env.SALT_ROUNDS || "10", 10);
const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET as string;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET as string;

function otpFn(length: number): string {
  let otp = "";
  for (let i = 0; i < length; i++) {
    otp += Math.floor(Math.random() * 10).toString(); // Generates a digit between 0 and 9
  }
  return otp;
}

// Send OTP for Register user
const sendOTP = async (req: Request, res: Response) => {
  const { email, userId } = req.body;

  try {
    // Check if the user exists
    let userResult = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    let userId: number;
    if (userResult.rows.length === 0) {
      // If user doesn't exist, create a new one
      const newUser = await pool.query(
        "INSERT INTO users (email) VALUES ($1) RETURNING id",
        [email]
      );
      userId = newUser.rows[0].id;
    } else {
      userId = userResult.rows[0].id;

      // If user is already verified, don't send OTP
      if (userResult.rows[0].is_verified) {
        return res.status(400).json({ message: "User already verified." });
      }
    }

    const otp = otpFn(6);

    // Generate OTP and expiration time
    const otpExpiration = new Date(
      Date.now() + +process.env.OTP_EXPIRY_MINUTES! * 60000
    ); // Set expiration time

    // console.log(`Generated OTP: ${otp}`); // Log the OTP

    console.log("Inserting OTP:", { userId, otp, otpExpiration });

    // Upsert OTP and expiration into the users table
    await pool.query(
      // `INSERT INTO otp_codes (user_id, email, otp_code, expires_at)
      //  VALUES ($1, $2, $3, $4)
      //  ON CONFLICT (user_id) DO UPDATE
      //  SET otp_code = $2, expires_at = $3`,
      // [userId, email, otp, otpExpiration]

      `INSERT INTO otp_codes (user_id, otp_code, expires_at, email) 
      VALUES ($1, $2, $3, $4) ON CONFLICT (user_id) 
      DO UPDATE SET otp_code = $2, expires_at = $3, email = $4`,
      [userId, otp, otpExpiration, email]
    );

    // Send OTP via email using SMTP
    await transporter.sendMail({
      from: `"Joy Karmakar" <${process.env.SMTP_USER}>`, // Sender address
      to: email,
      subject: "Your OTP for Registration",
      text: `Your OTP is ${otp}. It will expire in ${process.env.OTP_EXPIRY_MINUTES} minutes.`,
    });

    res.status(200).json({ message: "OTP sent successfully." });
  } catch (error) {
    console.error("Error sending OTP:", error);
    res.status(500).json({ message: "Error sending OTP." });
  }
};

// Verify OTP
const verifyOTP = async (req: Request, res: Response) => {
  const { email, otp } = req.body;

  try {
    // 1. Fetch the user by email
    const userResult = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: "User not found." });
    }

    console.log("User ID:", userResult.rows[0].id);

    const userId = userResult.rows[0].id;

    // 2. Fetch OTP details for the user
    const otpResult = await pool.query(
      "SELECT * FROM otp_codes WHERE user_id = $1",
      [userId]
    );

    if (otpResult.rows.length === 0) {
      return res
        .status(400)
        .json({ message: "OTP not found. Please request a new one." });
    }

    const otpRecord = otpResult.rows[0];

    // 3. Check if the OTP matches and is not expired
    const now = new Date();

    console.log("OTP Record:", otpRecord);

    if (otpRecord.otp_code !== otp) {
      return res.status(400).json({ message: "Invalid OTP." });
    }
    if (now > otpRecord.otp_expiration) {
      return res
        .status(400)
        .json({ message: "OTP has expired. Please request a new one." });
    }

    // 4. Mark the user as verified
    await pool.query("UPDATE users SET verified = TRUE WHERE id = $1", [
      userId,
    ]);

    // 5. Delete the OTP after successful verification
    await pool.query("DELETE FROM otp_codes WHERE user_id = $1", [userId]);

    res.status(200).json({ message: "User verified successfully." });
  } catch (error) {
    console.error("Error verifying OTP:", error);
    res.status(500).json({ message: "Error verifying OTP." });
  }
};

// Register new users (create user)
const registerUser = async (req: Request, res: Response): Promise<Response> => {
  const { username, password, email } = req.body;

  if (!username || !password || !email) {
    return res
      .status(400)
      .json({ message: "Username, Email, and password required" });
  }

  try {
    // Check if username or email already exists
    const userNameExists = await pool.query(
      "SELECT * FROM users WHERE username = $1",
      [username]
    );
    if (userNameExists.rows.length > 0) {
      return res.status(400).json({ message: "Username already taken" });
    }

    const userEmailExists = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );
    if (userEmailExists.rows.length > 0) {
      return res.status(400).json({ message: "Email already taken" });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    // Insert new user into the database
    const newUser = await pool.query(
      "INSERT INTO users (username, password, email) VALUES ($1, $2, $3) RETURNING id",
      [username, hashedPassword, email]
    );

    return res.status(201).json({
      message: "User created successfully",
      userId: newUser.rows[0].id,
    });
  } catch (err) {
    console.error(err);
    return res.sendStatus(500);
  }
};

// Login users and generate tokens
const loginUser = async (req: Request, res: Response): Promise<Response> => {
  const { username, password, email } = req.body;

  if ((username || email) && !password) {
    return res
      .status(400)
      .json({ message: "Username or Email and password required" });
  }

  try {
    const userResult = await pool.query(
      "SELECT * FROM users WHERE (username = $1 OR email = $2)",
      [username, email]
    );

    if (userResult.rows.length === 0) {
      return res
        .status(400)
        .json({ message: "Invalid username, email, or password" });
    }

    const user: User = userResult.rows[0];

    // Verify the password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ message: "Invalid username or password" });
    }

    // Generate tokens
    const accessToken = jwt.sign(
      { id: user.id, name: user.username },
      ACCESS_TOKEN_SECRET,
      { expiresIn: "15m" }
    );
    const refreshToken = jwt.sign(
      { id: user.id, name: user.username },
      REFRESH_TOKEN_SECRET
    );

    // Store refresh token in the database
    await pool.query(
      "INSERT INTO refresh_tokens (token, user_id) VALUES ($1, $2)",
      [refreshToken, user.id]
    );

    // Send refresh token as HTTP-only cookie
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,
    });

    return res.json({ accessToken });
  } catch (err) {
    console.error(err);
    return res.sendStatus(500);
  }
};

// Log out users and delete tokens
const logOutUser = async (req: Request, res: Response): Promise<Response> => {
  const { userId } = req.body;

  if (!userId) {
    return res.status(400).json({ message: "User ID is required" });
  }

  try {
    const message = await deleteOldToken(null, userId);
    return res.status(200).json({ message });
  } catch (err) {
    console.error("Logout error:", err);
    return res.sendStatus(500);
  }
};

// Generate new access token using refresh token
const token = async (req: Request, res: Response): Promise<Response> => {
  const refreshToken = req.cookies?.refreshToken;
  if (!refreshToken) {
    return res.sendStatus(403);
  }

  try {
    const tokenResult = await pool.query(
      "SELECT * FROM refresh_tokens WHERE token = $1",
      [refreshToken]
    );
    if (tokenResult.rows.length === 0) {
      return res.sendStatus(403);
    }

    return new Promise<Response>((resolve) => {
      jwt.verify(
        refreshToken,
        REFRESH_TOKEN_SECRET,
        (err: Error | null, decoded: any) => {
          if (err) {
            resolve(res.sendStatus(403));
          } else {
            const accessToken = jwt.sign(
              { id: decoded.id, name: decoded.name },
              ACCESS_TOKEN_SECRET,
              { expiresIn: "15m" }
            );

            resolve(res.json({ accessToken }));
          }
        }
      );
    });
  } catch (err) {
    console.error(err);
    return res.sendStatus(500);
  }
};

// Route to get all users
const getAllUsers = async (req: Request, res: Response) => {
  try {
    const result = await pool.query("SELECT * FROM users"); // Query the database
    res.status(200).json(result.rows); // Send query results as JSON
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
};

// Route to get a specific user by ID
const getUser = async (req: Request, res: Response) => {
  const { id } = req.params;

  try {
    const result = await pool.query("SELECT * FROM users WHERE id = $1", [id]);

    if (result.rows.length > 0) {
      res.status(200).json(result.rows[0]); // Return the user if found
    } else {
      res.status(404).json({ message: "User not found" });
    }
  } catch (error) {
    console.error("Error fetching user:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
};

// DELETE User Route
const deleteUser = async (req: Request, res: Response) => {
  const { id } = req.params; // Get user ID from route params

  try {
    const result = await pool.query("DELETE FROM users WHERE id = $1", [id]);

    if (result.rowCount && result.rowCount > 0) {
      res
        .status(200)
        .json({ message: `User with ID ${id} deleted successfully.` });
    } else {
      res.status(404).json({ message: `User with ID ${id} not found.` });
    }
  } catch (error) {
    console.error("Error deleting user:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
};

// PUT Route to Update User by ID
const updateUser = async (req: Request, res: Response) => {
  const { id } = req.params;
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({ message: "Password is required." });
  }

  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const result = await pool.query(
      "UPDATE users SET password = $1 WHERE id = $2 RETURNING *",
      [hashedPassword, id]
    );

    if (result.rowCount && result.rowCount > 0) {
      res.status(200).json({ message: "Password updated successfully." });
    } else {
      res.status(404).json({ message: "User not found." });
    }
  } catch (error) {
    console.error("Error updating password:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
};

export {
  registerUser,
  loginUser,
  logOutUser,
  token,
  sendOTP,
  verifyOTP,
  getAllUsers,
  getUser,
  deleteUser,
  updateUser,
};
