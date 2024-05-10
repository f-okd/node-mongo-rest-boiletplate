"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class AppError extends Error {
    constructor(message, statusCode) {
        super(message);
        this.statusCode = statusCode;
        this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
        this.isOperational = true;
        // Preserve error that just occured and not add this class to the stack trace
        // When a new object is created and the constructor is called, it wont pollute the stack trace
        Error.captureStackTrace(this, this.constructor);
    }
}
exports.default = AppError;
