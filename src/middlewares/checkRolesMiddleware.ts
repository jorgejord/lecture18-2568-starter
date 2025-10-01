import { type Request, type Response, type NextFunction } from "express";
import { type CustomRequest } from "../libs/types.js";
import { users } from "../db/db.js";
import type { User } from "../libs/types.js";

export const checkRoles = (
  req: CustomRequest,
  res: Response,
  next: NextFunction
) => {
  const payload = req.user;
  if (!payload) {
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

  // pass, actual per-endpoint permission (student can see only his own) will be implemented in route
  next();
};
