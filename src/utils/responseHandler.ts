import { Response } from "express";

export const sendResponse = (
  res: Response,
  statusCode: number,
  status: boolean,
  message: string,
  data: any = null
) => {
  return res.status(statusCode).json({
    status,
    message,
    data,
  });
};
