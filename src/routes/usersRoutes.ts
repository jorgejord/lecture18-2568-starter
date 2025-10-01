import { Router, type Request, type Response } from "express";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

import type { User, CustomRequest, UserPayload } from "../libs/types.js";
import { users, reset_users } from "../db/db.js";
import { authenticateToken } from "../middlewares/authenMiddleware.js";
import { checkRoleAdmin } from "../middlewares/checkRoleAdminMiddleware.js";

const router = Router();

const jwt_secret = process.env.JWT_SECRET || "this_is_my_secret";
const jwt_expires = process.env.JWT_EXPIRES || "1h";

router.get(
  "/",
  authenticateToken,
  checkRoleAdmin,
  (req: Request, res: Response) => {
    try {
      return res.json({
        success: true,
        data: users,
      });
    } catch (err) {
      return res.status(500).json({
        success: false,
        message: "Something is wrong, please try again",
        error: err,
      });
    }
  }
);

router.post("/login", (req: Request, res: Response) => {
  try {
    const { username, password } = req.body as {
      username?: string;
      password?: string;
    };

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: "username and password are required",
      });
    }

    const user = users.find(
      (u: User) => u.username === username && u.password === password
    );

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid username or password",
      });
    }

    const payload: UserPayload = {
      username: user.username,
      studentId: user.studentId ?? undefined,
      role: user.role,
    };

    const token = jwt.sign(payload, jwt_secret, { expiresIn: jwt_expires });

    (user.tokens = user.tokens ? [...user.tokens, token] : [token]);

    return res.status(200).json({
      success: true,
      message: "Login successful",
      token,
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Something is wrong, please try again",
      error: err,
    });
  }
});

router.post(
  "/logout",
  authenticateToken,
  (req: CustomRequest, res: Response) => {
    try {
      const payload = req.user;
      const token = req.token;

      if (!payload || !token) {
        return res.status(401).json({
          success: false,
          message: "Unauthorized user",
        });
      }

      const user = users.find((u: User) => u.username === payload.username);
      if (!user) {
        return res.status(401).json({
          success: false,
          message: "Unauthorized user",
        });
      }

      if (!user.tokens || !user.tokens.includes(token)) {
        return res.status(401).json({
          success: false,
          message: "Invalid token",
        });
      }

      user.tokens = user.tokens.filter((t) => t !== token);

      return res.status(200).json({
        success: true,
        message: "Logout successful",
      });
    } catch (err) {
      return res.status(500).json({
        success: false,
        message: "Something is wrong, please try again",
        error: err,
      });
    }
  }
);

router.post("/reset", (req: Request, res: Response) => {
  try {
    reset_users();
    return res.status(200).json({
      success: true,
      message: "User database has been reset",
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Something is wrong, please try again",
      error: err,
    });
  }
});

export default router;
