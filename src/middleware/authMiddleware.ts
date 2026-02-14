import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import User from "../models/User";
import { sendResponse } from "../utils/responseHandler";

interface AuthRequest extends Request {
  user?: any;
}

export const protect = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): Promise<any> => {
  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    try {
      // Get token from header
      token = req.headers.authorization.split(" ")[1];

      if (!token || token === "null" || token === "undefined") {
        return sendResponse(res, 401, false, "Authentication token is missing. Please log in to continue.");
      }

      // Verify token
      let decoded: any;
      try {
        decoded = jwt.verify(token, process.env.JWT_SECRET || "secret");
      } catch (jwtError: any) {
        if (jwtError.name === "TokenExpiredError") {
          return sendResponse(res, 401, false, "Your session has expired. Please log in again.");
        }
        if (jwtError.name === "JsonWebTokenError") {
          return sendResponse(res, 401, false, "Invalid authentication token. Please log in again.");
        }
        throw jwtError;
      }

      // Get user from the token
      req.user = await User.findById(decoded.id).select("-password");

      if (!req.user) {
        return sendResponse(res, 401, false, "User account not found. Please log in again.");
      }

      return next();
    } catch (error: any) {
      console.error("Auth middleware error:", error);
      return sendResponse(res, 401, false, "Authentication failed. Please log in again.");
    }
  }

  if (!token) {
    return sendResponse(res, 401, false, "Access denied. Please provide an authentication token to continue.");
  }
};

