import path from 'path';
import express from 'express';
// import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import ExpressMongoSanitize from 'express-mongo-sanitize';
import xss from 'xss-clean';
import hpp from 'hpp';
import cookieParser from 'cookie-parser';

import AppError from './utils/AppError';
import globalErrorHandler from './controllers/errorController';
import userRouter from './routes/userRoutes';

const app = express();

//1). Global Middlewares
//Serve static files
app.use(express.static(path.join(__dirname, 'public')));
// Set security HTTP headers
app.use(helmet());
// Development logging
// if (process.env.NODE_ENV === 'development') {
//   app.use(morgan('dev'));
// }
//Limit requests from the same API (100/hr)
const limiter = rateLimit({
  max: 100,
  windowMs: 60 * 60 * 100,
  message: 'Too many requests from this IP, please try again in an hour',
});
app.use('/api', limiter);
//Body parser, reading data from the body into req.body
app.use(express.json({ limit: '10kb' }));
//forms send data to server in a way called url coded, this middle ware lets us parse this type of data
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
//Parses cookie data
app.use(cookieParser());
//Data sanitisation against nosql query injection
app.use(ExpressMongoSanitize());
//Data sanitisation against xss
app.use(xss());
//Prevent parameter pollution
app.use(
  hpp({
    whitelist: [
      'duration',
      'numberOfRatings',
      'avgRating',
      'difficulty',
      'price',
    ], //allow multiple query params for duration (will select all matching), but not something like sort e.g.
  }),
);

// 3) Routes

//Health check
app.get('/api/v1/', (_req, res) => {
  res.status(200).json({
    status: 'success',
    data: 'OK',
  });
});
app.use('/api/v1/users', userRouter);

app.all('*', (req, _res, next) => {
  next(new AppError(`Can't find ${req.originalUrl}`, 404));
});

//Error handling middleware
app.use(globalErrorHandler);

export default app;
