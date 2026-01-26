"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sendResponse = void 0;
const sendResponse = (res, statusCode, status, message, data = null) => {
    return res.status(statusCode).json({
        status,
        message,
        data,
    });
};
exports.sendResponse = sendResponse;
