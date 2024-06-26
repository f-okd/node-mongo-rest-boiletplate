import { Schema } from 'mongoose';
import { IUser, Role } from '../models/userModel';
import { NextFunction, Request, Response } from 'express';

import crypto from 'crypto';
import { promisify } from 'util';
import jwt, { JwtPayload, Secret, SigningKeyCallback } from 'jsonwebtoken';
import AsyncErrorHandler from '../utils/AsyncErrorHandler';
import User from '../models/userModel';
import AppError from '../utils/AppError';
import Email from '../utils/Email';

export interface AuthenticatedRequest extends Request {
  user: IUser;
}

interface IDecodedPayload extends JwtPayload {
  id: string; // payload we passed into sign function (line:23)
  iat: number; //jwt.sign will add this property to payload
  exp: number; // We specified an expiration date so sign function will also add (line:24 )
}

const signToken = (id: Schema.Types.ObjectId) => {
  return jwt.sign({ id }, process.env.JWT_SECRET as Secret, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

const createAndSendToken = (user: IUser, statusCode: number, res: Response) => {
  const token = signToken(user._id as Schema.Types.ObjectId);
  const cookieOptions = {
    expires: new Date(
      Date.now() +
        Number(process.env.JWT_COOKIE_EXPIRES_IN) * 24 * 60 * 60 * 1000,
    ),
    secure: process.env.NODE_ENV === 'production' ? true : false,
    httpOnly: true,
  };

  res.cookie('jwt', token, cookieOptions);

  user.password = '';

  res.status(statusCode).json({
    status: 'success',
    token,
    data: {
      user,
    },
  });
};

export const signup = AsyncErrorHandler(
  async (req: Request, res: Response, _next: NextFunction) => {
    const newUser = await User.create({
      name: req.body.name,
      role: req.body.role,
      avatar: req.body.avatar,
      email: req.body.email,
      password: req.body.password,
      passwordConfirm: req.body.passwordConfirm,
      passwordChangedAt: req.body.passwordChangedAt,
    });

    createAndSendToken(newUser, 201, res);
  },
);

export const login = AsyncErrorHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const { email, password } = req.body;

    if (!email || !password) {
      return next(new AppError('Please provide email and password!', 400));
    }

    const user = await User.findOne({ email }).select('+password');

    if (!user || !(await user.correctPassword(password, user.password))) {
      return next(new AppError('Incorrect email or password', 401));
    }

    createAndSendToken(user, 200, res);
  },
);

export const logout = (_req: Request, res: Response, _next: NextFunction) => {
  res.cookie('jwt', 'Logged Out', {
    expires: new Date(Date.now()),
    httpOnly: true,
  });

  res.status(200).json({ status: 'success' });
};

export const protect = AsyncErrorHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    let token;
    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith('Bearer')
    ) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies.jwt) {
      token = req.cookies.jwt;
    }
    if (!token) {
      return next(new AppError('You are not logged in', 401));
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET as Secret);

    const currentUser = await User.findById((decoded as IDecodedPayload).id);
    if (!currentUser) {
      return next(
        new AppError('The user this token belongs to no longer exists', 401),
      );
    }

    if (currentUser.changedPasswordAfter((decoded as IDecodedPayload).iat)) {
      return next(
        new AppError(
          'User recently changed password! Please log in again',
          401,
        ),
      );
    }

    (req as AuthenticatedRequest).user = currentUser;
    next();
  },
);

export const restrictTo = (...roles: Role[]) => {
  return (req: Request, _res: Response, next: NextFunction) => {
    if (!roles.includes((req as AuthenticatedRequest).user.role)) {
      return next(
        new AppError('You do not have permission to perform this action', 403),
      );
    }
    next();
  };
};

export const forgotPassword = AsyncErrorHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const user = await User.findOne({ email: req.body.email });
    if (!user)
      return next(
        new AppError('There is no user with that email address.', 404),
      );
    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });

    try {
      const resetURL = `${req.protocol}://${req.get(
        'host',
      )}/api/v1/users/resetPassword/${resetToken}`;

      const message = `Forgot your password? Send patch request with new password and password confirmation to ${resetURL}`;

      await new Email(user).sendEmail({
        subject: 'Your password reset token (valid for 10min)',
        message,
      });

      res.status(200).json({
        status: 'success',
        message: 'token sent',
      });
    } catch (error) {
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save({ validateBeforeSave: false });

      return next(
        new AppError(
          'There was an error sending the email. Please try again later',
          500,
        ),
      );
    }
  },
);

export const resetPassword = AsyncErrorHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const hashedToken = crypto
      .createHash('sha256')
      .update(req.params.token)
      .digest('hex');
    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() },
    });

    if (!user) {
      return next(new AppError('Token is invalid or has expired', 400));
    }

    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    createAndSendToken(user, 200, res);
  },
);

const updatePassword = AsyncErrorHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const user = await User.findById(
      (req as AuthenticatedRequest).user._id,
    ).select('+password');

    if (!user) return next(new AppError('User not found', 404));

    if (
      !(await user.correctPassword(req.body.passwordCurrent, user.password))
    ) {
      return next(new AppError('Your current password is wrong.', 401));
    }

    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    await user.save();

    createAndSendToken(user, 200, res);
  },
);

export default {
  signup,
  login,
  logout,
  protect,
  restrictTo,
  forgotPassword,
  resetPassword,
  updatePassword,
};
