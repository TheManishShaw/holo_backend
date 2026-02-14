import { Request, Response, NextFunction } from "express";

export const errorHandler = (err: any, req: Request, res: Response, next: NextFunction) => {
  const statusCode = res.statusCode === 200 ? 500 : res.statusCode;

  // Handle JSON parsing errors (e.g. body-parser SyntaxError)
  if (err instanceof SyntaxError && 'body' in err && (err as any).type === 'entity.parse.failed') {
    return res.status(400).json({
      status: false,
      message: "Invalid JSON format in request body. Please check your data and try again.",
      data: null
    });
  }

  // Handle MongoDB CastError (invalid ObjectId)
  if (err.name === 'CastError') {
    return res.status(400).json({
      status: false,
      message: `Invalid ${err.path}: ${err.value}. Please provide a valid identifier.`,
      data: null
    });
  }

  // Handle MongoDB Validation Error
  if (err.name === 'ValidationError') {
    const messages = Object.values(err.errors).map((e: any) => e.message);
    return res.status(400).json({
      status: false,
      message: `Validation failed: ${messages.join(', ')}`,
      data: null
    });
  }

  // Handle MongoDB Duplicate Key Error
  if (err.code === 11000) {
    const field = Object.keys(err.keyPattern)[0];
    return res.status(409).json({
      status: false,
      message: `This ${field} is already in use. Please use a different ${field}.`,
      data: null
    });
  }

  // Handle JWT errors
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({
      status: false,
      message: "Invalid authentication token. Please log in again.",
      data: null
    });
  }

  if (err.name === 'TokenExpiredError') {
    return res.status(401).json({
      status: false,
      message: "Your session has expired. Please log in again.",
      data: null
    });
  }

  // Default error response
  res.status(statusCode).json({
    status: false,
    message: err.message || "An unexpected error occurred. Please try again later.",
    data: null,
    ...(process.env.NODE_ENV === "development" && { stack: err.stack })
  });
};
