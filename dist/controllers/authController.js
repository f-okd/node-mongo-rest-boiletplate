"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.resetPassword = exports.forgotPassword = exports.restrictTo = exports.isLoggedIn = exports.protect = exports.logout = exports.login = exports.signup = void 0;
const crypto_1 = __importDefault(require("crypto"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const AsyncErrorHandler_1 = __importDefault(require("../utils/AsyncErrorHandler"));
const userModel_1 = __importDefault(require("../models/userModel"));
const AppError_1 = __importDefault(require("../utils/AppError"));
const signToken = (id) => {
    return jsonwebtoken_1.default.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN,
    });
};
const createAndSendToken = (user, statusCode, res) => {
    const token = signToken(user._id);
    const cookieOptions = {
        expires: new Date(Date.now() +
            Number(process.env.JWT_COOKIE_EXPIRES_IN) * 24 * 60 * 60 * 1000),
        secure: process.env.NODE_ENV === 'production' ? true : false, //cookie will only be sent on an encrypted connect
        httpOnly: true, //cookie cant be accessed/manipulated by browser (xss attacks)
    };
    // expire property ensures that the client will delete the cookie after it has expired
    res.cookie('jwt', token, cookieOptions);
    //remove password from the output
    user.password = '';
    res.status(statusCode).json({
        status: 'success',
        token,
        data: {
            user,
        },
    });
};
exports.signup = (0, AsyncErrorHandler_1.default)((req, res, _next) => __awaiter(void 0, void 0, void 0, function* () {
    const newUser = yield userModel_1.default.create({
        name: req.body.name,
        role: req.body.role,
        avatar: req.body.avatar,
        email: req.body.email,
        password: req.body.password,
        passwordConfirm: req.body.passwordConfirm,
        passwordChangedAt: req.body.passwordChangedAt,
    });
    // Expiration time will logut user after x minutes even if it would otherwise verify
    createAndSendToken(newUser, 201, res);
}));
exports.login = (0, AsyncErrorHandler_1.default)((req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    const { email, password } = req.body;
    // 1) Check if email and password exist
    if (!email || !password) {
        return next(new AppError_1.default('Please provide email and password!', 400));
    }
    // 2) Check if user exists && password is correct
    const user = yield userModel_1.default.findOne({ email }).select('+password');
    // console.log(user);
    if (!user || !(yield user.correctPassword(password, user.password))) {
        return next(new AppError_1.default('Incorrect email or password', 401));
    }
    // 3) If everything okay send token to client
    createAndSendToken(user, 200, res);
}));
const logout = (req, res, _next) => {
    res.cookie('jwt', 'Logged Out', {
        expires: new Date(Date.now()),
        httpOnly: true,
    });
    res.status(200).json({ status: 'success' });
};
exports.logout = logout;
exports.protect = (0, AsyncErrorHandler_1.default)((req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    // 1) Check if token exists and retrieve it
    let token;
    if (req.headers.authorization &&
        req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }
    else if (req.cookies.jwt) {
        token = req.cookies.jwt;
    }
    if (!token) {
        // 401: Unauthorised
        return next(new AppError_1.default('You are not logged in', 401));
    }
    // 2) Verify JWT token
    // Callback runs after the verifying
    const decoded = jsonwebtoken_1.default.verify(token, process.env.JWT_SECRET);
    // console.log(decoded);
    // 3) Check if user still exists
    const currentUser = yield userModel_1.default.findById(decoded.id);
    // console.log(currentUser);
    if (!currentUser) {
        return next(new AppError_1.default('The user this token belongs to no longer exists', 401));
    }
    // 4) Check if user changed password after the JWT was issued
    //JWT stores date of issue
    if (currentUser.changedPasswordAfter(decoded.iat)) {
        return next(new AppError_1.default('User recently changed password! Please log in again', 401));
    }
    //GRANT ACCESS TO PROTECTED ROUTE
    res.locals.user = currentUser;
    req.user = currentUser;
    next();
}));
// Only for rendered pages, no errors!
const isLoggedIn = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    if (req.cookies.jwt) {
        try {
            // 1) verify token
            const decoded = jsonwebtoken_1.default.verify(req.cookies.jwt, process.env.JWT_SECRET);
            // 2) Check if user still exists
            const currentUser = yield userModel_1.default.findById(decoded.id);
            if (!currentUser) {
                return next();
            }
            // 3) Check if user changed password after the token was issued
            if (currentUser.changedPasswordAfter(decoded.iat)) {
                return next();
            }
            // THERE IS A LOGGED IN USER
            res.locals.user = currentUser;
            return next();
        }
        catch (err) {
            return next();
        }
    }
    next();
});
exports.isLoggedIn = isLoggedIn;
const restrictTo = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return next(new AppError_1.default('You do not have permission to perform this action', 403));
        }
        next();
    };
};
exports.restrictTo = restrictTo;
exports.forgotPassword = (0, AsyncErrorHandler_1.default)((req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    // 1. Get user based on POSTed email
    const user = yield userModel_1.default.findOne({ email: req.body.email });
    if (!user)
        return next(new AppError_1.default('There is no user with that email address.', 404));
    // 2. Generate random token
    const resetToken = user.createPasswordResetToken();
    yield user.save({ validateBeforeSave: false });
    // 3. Send to user's email
    const resetURL = `${req.protocol}://${req.get('host')}/api/v1/users/resetPassword/${resetToken}`;
    const message = `Forgot your password? Send patch req with new password and password confirmation to ${resetURL}`;
    try {
        // await sendEmail({
        //   email: user.email,
        //   subject: 'Your password reset token (valid for 10min)',
        //   message,
        // });
        //We send the token in plaintext because we assume the email to be a safe secure place that only the user has access to
        res.status(200).json({
            status: 'success',
            message: 'token sent',
        });
    }
    catch (error) {
        // If unsuccessful, reset token
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        yield user.save({ validateBeforeSave: false });
        return next(new AppError_1.default('There was an error sending the email. Please try again later', 500));
    }
}));
exports.resetPassword = (0, AsyncErrorHandler_1.default)((req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    // 1) Get user based on token
    const hashedToken = crypto_1.default
        .createHash('sha256')
        .update(req.params.token)
        .digest('hex');
    const user = yield userModel_1.default.findOne({
        passwordResetToken: hashedToken,
        passwordResetExpires: { $gt: Date.now() },
    });
    // 2) If token has not expired, and user exists, set the new password
    if (!user) {
        return next(new AppError_1.default('Token is invalid or has expired', 400));
    }
    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    user.passwordResetToken = '';
    user.passwordResetExpires = new Date(0);
    yield user.save();
    // 3) Update changedPasswordAt propery for the user
    // 4) Log the user in, send JWT
    createAndSendToken(user, 200, res);
}));
const updatePassword = (0, AsyncErrorHandler_1.default)((req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    // 1) Get user from collection
    const user = yield userModel_1.default.findById(req.user._id).select('+password');
    if (!user)
        return next(new AppError_1.default('User not found', 404));
    // 2) Check if POSTed current password is correct
    if (!(yield user.correctPassword(req.body.passwordCurrent, user.password))) {
        return next(new AppError_1.default('Your current password is wrong.', 401));
    }
    // 3) If so, update password
    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    yield user.save();
    // User.findByIdAndUpdate will NOT work as intended!
    // 4) Log user in, send JWT
    createAndSendToken(user, 200, res);
}));
exports.default = {
    signup: exports.signup,
    login: exports.login,
    logout: exports.logout,
    protect: exports.protect,
    isLoggedIn: exports.isLoggedIn,
    restrictTo: exports.restrictTo,
    forgotPassword: exports.forgotPassword,
    resetPassword: exports.resetPassword,
    updatePassword,
};
