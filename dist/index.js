"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const path_1 = __importDefault(require("path"));
const express_1 = __importDefault(require("express"));
// import morgan from 'morgan';
const express_rate_limit_1 = __importDefault(require("express-rate-limit"));
const helmet_1 = __importDefault(require("helmet"));
const express_mongo_sanitize_1 = __importDefault(require("express-mongo-sanitize"));
const xss_clean_1 = __importDefault(require("xss-clean"));
const hpp_1 = __importDefault(require("hpp"));
const cookie_parser_1 = __importDefault(require("cookie-parser"));
const AppError_1 = __importDefault(require("./utils/AppError"));
// const globalErrorHandler = require('./controllers/errorController');
const userRoutes_1 = __importDefault(require("./routes/userRoutes"));
const app = (0, express_1.default)();
//1). Global Middlewares
//Serve static files
app.use(express_1.default.static(path_1.default.join(__dirname, 'public')));
// Set security HTTP headers
app.use((0, helmet_1.default)());
// Development logging
// if (process.env.NODE_ENV === 'development') {
//   app.use(morgan('dev'));
// }
//Limit requests from the same API (100/hr)
const limiter = (0, express_rate_limit_1.default)({
    max: 100,
    windowMs: 60 * 60 * 100,
    message: 'Too many requests from this IP, please try again in an hour',
});
app.use('/api', limiter);
//Body parser, reading data from the body into req.body
app.use(express_1.default.json({ limit: '10kb' }));
//forms send data to server in a way called url coded, this middle ware lets us parse this type of data
app.use(express_1.default.urlencoded({ extended: true, limit: '10kb' }));
//Parses cookie data
app.use((0, cookie_parser_1.default)());
//Data sanitisation against nosql query injection
app.use((0, express_mongo_sanitize_1.default)());
//Data sanitisation against xss
app.use((0, xss_clean_1.default)());
//Prevent parameter pollution
app.use((0, hpp_1.default)({
    whitelist: [
        'duration',
        'numberOfRatings',
        'avgRating',
        'difficulty',
        'price',
    ], //allow multiple query params for duration (will select all matching), but not something like sort e.g.
}));
// 3) Routes
//Health check
app.get('/api/v1/', (_req, res) => {
    res.status(200).json({
        status: 'success',
        data: 'OK',
    });
});
app.use('/api/v1/users', userRoutes_1.default);
app.all('*', (req, _res, next) => {
    next(new AppError_1.default(`Can't find ${req.originalUrl}`, 404));
});
//Error handling middleware
// app.use(globalErrorHandler);
exports.default = app;
