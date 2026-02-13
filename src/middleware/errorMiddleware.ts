import { Request, Response, NextFunction } from "express";

export const errorHandler = (err: any, req: Request, res: Response, next: NextFunction) => {
  const statusCode = res.statusCode === 200 ? 500 : res.statusCode;

  // Handle JSON parsing errors (e.g. body-parser SyntaxError)
  if (err instanceof SyntaxError && 'body' in err && (err as any).type === 'entity.parse.failed') {
    return res.status(400).json({
      status: false,
      message: "Invalid JSON format. Please check your request body."
    });
  }

  res.status(statusCode).json({
    status: false,
    message: err.message || "Internal Server Error",
    stack: process.env.NODE_ENV === "production" ? null : err.stack,
  });
};
