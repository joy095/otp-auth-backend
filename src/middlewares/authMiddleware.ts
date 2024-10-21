/** @format */
import jwt from "jsonwebtoken";
import { Request, Response, NextFunction } from "express";

import pool from "../config/db";

const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;

// Logout route that deletes the user's refresh token
// Delete old token function
const deleteOldToken = async (token = null, userId = null) => {
  try {
    if (token) {
      const result = await pool.query(
        "DELETE FROM refresh_tokens WHERE token = $1",
        [token]
      );
      return result.rowCount && result.rowCount > 0
        ? "Token deleted successfully"
        : "Token not found";
    }

    if (userId) {
      const result = await pool.query(
        "DELETE FROM refresh_tokens WHERE user_id = $1",
        [userId]
      );
      return result.rowCount && result.rowCount > 0
        ? "User tokens deleted successfully"
        : "No tokens found for this user";
    }

    return "Token or User ID required for deletion";
  } catch (err) {
    console.error("Error deleting token:", err);
    return "Error deleting token";
  }
};
// Middleware to authenticate access tokens
const authenticateToken = (req: Request, res: Response, next: NextFunction) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.sendStatus(401); // No token found

  if (!ACCESS_TOKEN_SECRET) {
    console.error("ACCESS_TOKEN_SECRET is not defined");
    return res.sendStatus(500); // Internal Server Error
  }

  jwt.verify(token, ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // Invalid token
    (req as any).user = user;
    next();
  });
};

export { authenticateToken, deleteOldToken };
