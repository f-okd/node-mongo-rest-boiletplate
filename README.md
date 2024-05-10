h1 NodeJS + MongoDB REST API Boilerplate

h2 How to Run

Only data we pass in jwt payload is the user id (jwt.sign({id}))
JWT_SECRET: - Using hs256 encryption for the signature, secret should be at least 32characters long. The longer the better
JWT_EXPIRES_IN - Duration for which jwt token should be considered valid,even if the signature is correct. e.g. logging out the user after a certain period of time - Additional security measure

h2 How to test

h3 Security

h4 How Json Web Tokens (JWTs) work:

- Stateless solution to authentication, so we don't need to store any session state on the server
- User client makes POST req to /login end point. If the user exists and the password is correct, a unique JWT is created using a secret.
- In this app we use the jwt package
- Server sends the JWT back to the client, it's stored in it's cookies or local storage. With this, the user is basically logged in to the application
- Subsequent requests from the client to protected routes on the server will have the JWT attached to it. The server will verify (check data is unmodified and token has not expired) the token and then allow access and send requested data to the client.
- Incredibly important to keep your secret private.

h5 JWT on this app:

```
// src\controllers\authController.ts:16
interface IDecodedPayload extends JwtPayload {
  id: string; // payload we passed into sign function (line:23)
  iat: number; //jwt.sign will add this property to payload
  exp: number; // We specified an expiration date so sign function will also add (line:24 )
}
```

h4 Authentication + Authorization:

**Logging in**:

```
// pass in userID as payload, get jwt secret from env, and add expiry date in options, then create signature
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

export const login = AsyncErrorHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const { email, password } = req.body;

    // 1. Check if email and password exist
    if (!email || !password) {
      return next(new AppError('Please provide email and password!', 400));
    }
    // 2. Check if user exists && password is correct
    const user = await User.findOne({ email }).select('+password');

    if (!user || !(await user.correctPassword(password, user.password))) {
      return next(new AppError('Incorrect email or password', 401));
    }

    // 3. If everything okay send token to client
    createAndSendToken(user, 200, res);
  },
);
```

**Logging Out**:

- We override the user's currently stored jwt with a meaningless value, so they'll need to log in again and get a new valid one from the server.

```
export const logout = (req: Request, res: Response, _next: NextFunction) => {
  res.cookie('jwt', 'Logged Out', {
    expires: new Date(Date.now()),
    httpOnly: true,
  });

  res.status(200).json({ status: 'success' });
};
```

**Protecting routes**:

We create a 'protect' middleware to verify jwts before returning requested data:

```
// src/routes/userRoutes:
router.use(authController.protect);
router.patch('/updateMyPassword/', authController.updatePassword);

// src/controllers/authController:
export const protect = AsyncErrorHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    // 1. Check if token exists and retrieve it
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
      // 401: Unauthorised
      return next(new AppError('You are not logged in', 401));
    }

    // 2. Verify JWT token
    // Callback runs after the verifying
    const decoded = jwt.verify(token, process.env.JWT_SECRET as Secret);

    // 3. Check if user still exists
    const currentUser = await User.findById((decoded as IDecodedPayload).id);
    if (!currentUser) {
      return next(
        new AppError('The user this token belongs to no longer exists', 401),
      );
    }

    // 4. Check if user changed password after the JWT was issued
    //JWT stores date of issue
    if (currentUser.changedPasswordAfter((decoded as IDecodedPayload).iat)) {
      return next(
        new AppError(
          'User recently changed password! Please log in again',
          401,
        ),
      );
    }

    //GRANT ACCESS TO PROTECTED ROUTE
    (req as AuthenticatedRequest).user = currentUser;
    next();
  },
);

```

**Role based authentication/Restricting routes to specific user roles**

```
export const restrictTo = (...roles: Role[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!roles.includes((req as AuthenticatedRequest).user.role)) {
      return next(
        new AppError('You do not have permission to perform this action', 403),
      );
    }
    next();
  };
};
```

h4 Resetting Passwords

- User sends post request to /forgotPassword route with email in the body, handler creates reset token and sends to the email address provided. (Regular token, not a JWT so we feel comfortable sending in plaintext as the email should be a secure place)
- User sends the token sent to his email with their new password in order to update their password, feel free to implement this

**/forgotPassword**

```
userSchema.methods.createPasswordResetToken = function () {
  //don't store in db as plaintext as if a bad actor gains db access they can use it to reset the user's password
  const resetToken = crypto.randomBytes(32).toString('hex');

  // use sha256 algo to encrypt resetToken and store as hex again
  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  console.log({ resetToken }, this.passwordResetToken);

  this.passwordResetExpires = new Date(Date.now() + 10 * 60 * 1000);

  return resetToken;
};

export const forgotPassword = AsyncErrorHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    // 1. Get user based on POSTed email
    const user = await User.findOne({ email: req.body.email });
    if (!user)
      return next(
        new AppError('There is no user with that email address.', 404),
      );
    // 2. Generate random token
    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });
    // 3. Send to user's email
    const resetURL = `${req.protocol}://${req.get(
      'host',
    )}/api/v1/users/resetPassword/${resetToken}`;

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
    } catch (error) {
      // If unsuccessful, reset token
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
```

**Resetting password**

```

```

**Updating password**

- Protected route, user must be logged in to access this handler => user property will be available on request object
- user.correctPassword() is a mongoose instance method, we use to check if a submitted value is equal to that user instance's set passord

```
const updatePassword = AsyncErrorHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    // 1. Get user from collection
    const user = await User.findById(
      (req as AuthenticatedRequest).user._id,
    ).select('+password');

    if (!user) return next(new AppError('User not found', 404));

    // 2. Check if POSTed current password is correct
    if (
      !(await user.correctPassword(req.body.passwordCurrent, user.password))
    ) {
      return next(new AppError('Your current password is wrong.', 401));
    }

    // 3. If so, update password
    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    await user.save();
    // User.findByIdAndUpdate will NOT work as intended!

    // 4. Log user in, send JWT
    createAndSendToken(user, 200, res);
  },
);
```
