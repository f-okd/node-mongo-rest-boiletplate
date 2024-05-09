interface AppError extends Error {
  status: string;
  statusCode: Number;
  isOperational: Boolean;
}

class AppError extends Error {
  constructor(message: string, statusCode: Number) {
    super(message);
    this.statusCode = statusCode;
    this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
    this.isOperational = true;

    // Preserve error that just occured and not add this class to the stack trace
    // When a new object is created and the constructor is called, it wont pollute the stack trace
    Error.captureStackTrace(this, this.constructor);
  }
}

export default AppError;
