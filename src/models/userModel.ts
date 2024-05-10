import mongoose, {
  Schema,
  Document,
  Query,
  QueryWithHelpers,
  HydratedDocument,
  Model,
} from 'mongoose';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import validator from 'validator';

export enum Role {
  ADMIN = 'admin',
  ROLE1 = 'exampleRole1',
  ROLE2 = 'exampleRole2',
}

interface UserQueryHelpers {
  activeAccounts(
    name: string,
  ): QueryWithHelpers<
    HydratedDocument<IUser>[],
    HydratedDocument<IUser>,
    UserQueryHelpers
  >;
}

export interface IUser extends Document {
  _id: Schema.Types.ObjectId;
  name: string;
  email: string;
  avatar?: string;
  role: Role;
  password: string;
  passwordConfirm: string;
  passwordChangedAt?: Date;
  passwordResetToken?: string;
  passwordResetExpires?: Date;
  active: boolean;
}

interface IUserMethods {
  correctPassword(
    candidatePassword: string,
    userPassword: string,
  ): Promise<boolean>;
  createPasswordResetToken: () => string;
  changedPasswordAfter: (JWTTimestamp: number) => boolean;
}

type UserModel = Model<IUser, UserQueryHelpers, IUserMethods>;

const userSchema = new Schema<IUser, UserModel, IUserMethods, UserQueryHelpers>(
  {
    name: {
      type: String,
      required: [true, 'User must have a name'],
    },
    email: {
      type: String,
      unique: true,
      required: [true, 'User must have an associated email'],
      lowercase: true,
      validate: {
        validator: (val: string) => {
          return validator.isEmail(val);
        },
        message: 'Tour name must only contain letters',
      },
    },
    avatar: { type: String, default: 'default.jpg' },
    role: {
      type: String,
      enum: Object.values(Role),
      default: Role.ROLE1,
    },
    password: {
      type: String,
      required: [true, 'User must provide a password'],
      minLength: 8,
      select: false,
    },
    passwordConfirm: {
      type: String,
      required: [true, 'User must provide a password confirmation'],
    },
    passwordChangedAt: Date,
    passwordResetToken: String,
    passwordResetExpires: Date,
    active: {
      type: Boolean,
      default: true,
      select: false,
    },
  },
);

userSchema.query.activeAccounts = function (
  this: QueryWithHelpers<any, HydratedDocument<IUser>, UserQueryHelpers>,
) {
  return this.find({ active: { $ne: false } });
};

userSchema.methods.correctPassword = async function (
  // this.password not availble because we disabled select
  candidatePassword: string,
  userPassword: string,
) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

userSchema.methods.changedPasswordAfter = function (JWTTimestamp: number) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(
      (this.passwordChangedAt.getTime() / 1000).toString(), // Convert number to string
      10,
    );

    return JWTTimestamp < changedTimestamp;
  }

  // False means NOT changed
  return false;
};

userSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString('hex');

  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  console.log({ resetToken }, this.passwordResetToken);

  this.passwordResetExpires = new Date(Date.now() + 10 * 60 * 1000);

  return resetToken;
};

//for all querys beginning with find
userSchema.pre(/^find/, function (next) {
  //this points to the current query
  (this as Query<any, HydratedDocument<IUser>, UserQueryHelpers>).find({
    active: { $ne: false },
  });
  next();
});
userSchema.pre('save', async function (next) {
  //Only run this function if the password was modified
  if (!this.isModified('password')) return next();

  //Hash the password with a cost of 12, the higher the more CPU intensive the operation (duration)
  this.password = await bcrypt.hash(this.password, 12);

  // Delete the password confirm field
  // It's a required input not that it's required to be persisted to the db, thats why we can remove it here
  this.passwordConfirm = '';

  this.passwordChangedAt = new Date(Date.now());
});

userSchema.pre('save', async function (next) {
  if (!this.isModified('password') || this.isNew) return next();

  // sometimes takes longer to save in db than to send jwt so it makes it look like password was changed after jwt createdAt, so we subtract 1s
  this.passwordChangedAt = new Date(Date.now() - 1000);
  next();
});

const User = mongoose.model('User', userSchema);

export default User;
