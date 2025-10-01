import { type Request, type Response, type NextFunction } from "express";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

import { type CustomRequest, type UserPayload } from "../libs/types.js";
import { users } from "../db/db.js";
import type { User } from "../libs/types.js";

export const authenticateToken = (
  req: CustomRequest,
  res: Response,
  next: NextFunction
) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      message: "Authorization header is required",
    });
  }

  const token = authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Token is required",
    });
  }

  const jwt_secret = process.env.JWT_SECRET || "this_is_my_secret";

  jwt.verify(token, jwt_secret, (err, payload) => {
    if (err) {
      return res.status(403).json({
        success: false,
        message: "Invalid or expired token",
      });
    }

    const userPayload = payload as UserPayload;

    const user = users.find((u: User) => u.username === userPayload?.username);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized user",
      });
    }

    if (user.tokens && !user.tokens.includes(token)) {
      return res.status(403).json({
        success: false,
        message: "Invalid token",
      });
    }

    req.user = userPayload;
    req.token = token;

    next();
  });
};
