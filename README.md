# NodeJS + MongoDB REST API Boilerplate

## Table of Contents

- [How to run](#how-to-run)
- [How to test](#how-to-test)
- [Security](#security)
  - [Best practices implemented](#best-practices-implemented)
  - [How Json Web Tokens (JWTs) work](#how-json-web-tokens-jwts-work)
  - [Authentication + Authorization](#authentication--authorization)
- [Image Uploads](#image-uploads)

## How to Run

Follow these steps to clone and run the project on your local machine:

1. Clone the repository to your local machine:

   ```bash
   git clone https://github.com/f-okd/book-tracker
   ```

2. Navigate to the project directory:

   ```bash
   cd C:\...\node-mongo-rest-boilerplate
   ```

3. Install dependencies:

   ```bash
   npm install
   ```

4. Rename the env.example file and populate the variables:

   - You will need to create a mongodb account and a new database so that you can use that connection string
   - You will need a 32 character long JWT secret
   - You will need a mailtrap account for testing emails in development environment

5. Run the development server:
   ```bash
   npm run dev
   ```

You should be able to send requests the application at http://localhost:3000 if you left the port as it stands.

User avatars will be stored locally @public/img/users
I recommend you reconfigure this and use a storage bucket for your applications.

## How to test

- Download the POSTMAN Collection and experiment with the requests.
- You will need to populate the Environment variables.

[<img src="https://run.pstmn.io/button.svg" alt="Run In Postman" style="width: 128px; height: 32px;">](https://app.getpostman.com/run-collection/28686808-3c87380a-3c09-4028-a850-6c4279471768?action=collection%2Ffork&source=rip_markdown&collection-url=entityId%3D28686808-3c87380a-3c09-4028-a850-6c4279471768%26entityType%3Dcollection%26workspaceId%3Dbb762fa1-92b3-4428-81d0-0351acacea3c)

I recommend creating an admin account first:

```
POST {{URL}}/api/v1/users/signup
        body {
            "name":"Test admin",
            "email":"test@example.com",
            "role":"admin",
            "password":"test1234",
            "passwordConfirm":"test1234"
        }
```

I recommend after you create a master admin account, add a middleware to not allow non-admin/authenticated users to create new admin accounts. It's currently open so you can make the first admin account.

Example postman environment variables:
| Variable | Type | Value |
|--------------|---------|-------------|
| url | String | http://127.0.0.1:3000 |
| jwt | String | |
| admin_email | String |admin@appName.com |
| user_email | String | user1@appName.com|
| password | String | test1234|

## Security

### Best practices implemented:

- Passwords are strongly encrypted wiht salt and hash (bcrpyt.js)
- Password reset tokens are also strongly encrypted (SHA 256)
- Rate limiter (express-rate-limit) used to protect vs brute force attacks e.g. DDOS
- Prevent XSS attacks by only sending jwts in HTTOnly cookies, meaning the browser can only receive and send cookies but can't acceess or modify them
- Use helmet package to set special HTTP headers to protect vs xss attacks
- Because we're using mongoose which comes with SchemaTypes its harder to fall prey to NSQL Query injection
- User inputs are well sanitized
- Can use hpp package to prevent parameter pollution (so we whitelist a fixed set of acceptable query params)

### How Json Web Tokens (JWTs) work:

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

### Authentication + Authorization:

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

- We create a 'protect' middleware to verify jwts before returning requested data.
- After verifying everything's okay, user property will be available on request object so the following handlers can use it for db look ups. e.g. `find({id:req.user.id})`

- src/routes/userRoutes:

```
router.use(authController.protect);
router.patch('/updateMyPassword/', authController.updatePassword);
```

- src/controllers/authController:

```
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

- User property will be available on request object as it should be used after the protect middleware
  If a user is logged in (gets past protect middleware), but doesn't have the desired role...they'll not be allowed to access the following handler (re:middleware stack).

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

#### Resetting Passwords

- User sends post request to `/forgotPassword` route with their email in the request body.
- The server creates reset token and stores in the db on user document.
- The token is also to the email address provided. (Regular token, not a JWT so we feel comfortable sending in plaintext as the email should be a secure place)
- Token is like a temporary password (will expire in 10minutes) so we encrypt it, althought it doesn't need to be as cryptographically strong as the password encryption as because it's a weaker attack vector.

**/forgotPassword**

```
// src\models\userModel.ts
userSchema.methods.createPasswordResetToken = function () {
  // cant store in db as plaintext as if a bad actor gains db access they can use it to reset the user's password
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
```

- We use sendgrid as our production service, and mailtrap as our development service.
- Mailtrap intercepts outgoing emails for testing.

```
//src\controllers\authController.ts
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
      //haven't specified all the mandatory/required fields specified in schema, so we need to not validate to prevent errors e.g. password
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

- To change the password the client must send a PATCH request to {{URL}}/api/v1/users/resetPassword/:token' with a new password and password confirmation in the body:
  {
  "email":"test@example.com",
  "password":
  }
- Because the forgotPassword route has appended a resetToken to the user document, we can rehash the plaintext token sent in the request params and look for the user document that has a matching hashed token.
- If the token is not expired we change the user's password and reset their resetToken properties
- When the NODE_ENV environment variable = "development", it will use nodemailer and then all outgoing emails will be show in your nodemailer inbox, but not actually be sent to the address specified.
- However when the NODE_ENV environment variable = "production", it will use sendgrid as the email service. (I recommend choosing another service, as sendgrid can be hard for hobbyists to get started with. However I've provided the template code to support it based on their documentation)
- You could extend this and send html in the email body instead of plain text.

```
export const resetPassword = AsyncErrorHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    // 1. Get user based on token
    const hashedToken = crypto
      .createHash('sha256')
      .update(req.params.token)
      .digest('hex');
    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() },
    });
    // 2. If token has not expired, and user exists, set the new password

    if (!user) {
      return next(new AppError('Token is invalid or has expired', 400));
    }

    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    user.passwordResetToken = '';
    user.passwordResetExpires = new Date(0);
    await user.save();
    // 3. Update changedPasswordAt propery for the user
    // 4. Log the user in, send JWT
    createAndSendToken(user, 200, res);
  },
);
```

**Updating password**

- Protected route, user must be logged in to access this handler
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

**Update password**

- This route is for authenticated users (already logged in) to change their password
- They pass a password and a confirmation to the request body and once they're validated, the user password is updated and they're sent a new jwt

```
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


    // dont use findByIdAndUpdate otherwise the validators and defined pre-save middleware won't run
    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    await user.save();

    createAndSendToken(user, 200, res);
  },
);
```

## Image Uploads

By default images will be sent via multer upload. Multer is a nodejs middlware that we use to handle multipart/form-data, in this app we use it to handle image uploads.

In the {POST} `/users/updateMe` route, the client can send an image in the `avatar` field and it will be uploaded to the specified location. In this app it is just uploaded to the public folder, so as to not bog users down with config settings. [You can configure it to upload to a specified S3 bucket though](https://medium.com/@mbakr1/uploading-files-to-s3-in-node-js-using-multer-1f8bac1c2ddc)

We save the file uploaded in the request as a buffer and check that it's an image before uploading to the specified destination.
Because we used `upload.single` it will only accept one file in the `avatar` form-data field otherwise it will throw an error, it will also throw an error if a non-image is sent in that field.

```
//Image stored as buffer, which is available at req.file.buffer, dont have to write file to disk then read it again
const multerStorage = multer.memoryStorage();

const multerFilter = (
  _req: Request,
  file: Express.Multer.File,
  cb: FileFilterCallback,
) => {
  if (file.mimetype.startsWith('image')) {
    cb(null, true);
  } else {
    cb(new AppError('Please only upload Images', 400));
  }
};

const upload = multer({
  storage: multerStorage,
  fileFilter: multerFilter,
});

//'single' field in form that will contain image to upload, singlE:1 file.
// Will copy file and put in destination and put information about it on the request
const uploadUserPhoto = upload.single('avatar');
```
