/** @format */

import { Router, Request, Response, Application } from "express";
import {
  loginUser,
  logOutUser,
  registerUser,
  sendOTP,
  verifyOTP,
  getUser,
  getAllUsers,
  deleteUser,
  updateUser,
} from "../controllers/userController";
import { authenticateToken } from "../middlewares/authMiddleware";

const router = Router();

router.post("/send-otp", sendOTP as Application);

router.post("/verify-otp", verifyOTP as Application);

router.get("/", getAllUsers as Application);

router.get("/:id", getUser as Application);

router.delete("/:id", deleteUser as Application);

router.patch("/:id", updateUser as Application);

router.post("/register", registerUser as Application);

router.post("/login", loginUser as Application);

router.post("/logout", logOutUser as Application);

router.post("/token", logOutUser as Application);

// Protected route
router.get(
  "/protected",
  authenticateToken as unknown as Application,
  (req: Request & { user?: { name: string } }, res: Response) => {
    const userName = req.user?.name;
    res.json({ message: `Hello ${userName}, you are authenticated.` });
  }
);

export default router;
