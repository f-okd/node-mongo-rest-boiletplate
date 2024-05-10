"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
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
exports.Role = void 0;
const mongoose_1 = __importStar(require("mongoose"));
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const crypto_1 = __importDefault(require("crypto"));
const validator_1 = __importDefault(require("validator"));
var Role;
(function (Role) {
    Role["ADMIN"] = "admin";
    Role["ROLE1"] = "exampleRole1";
    Role["ROLE2"] = "exampleRole2";
})(Role || (exports.Role = Role = {}));
const userSchema = new mongoose_1.Schema({
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
            validator: (val) => {
                return validator_1.default.isEmail(val);
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
});
userSchema.query.activeAccounts = function () {
    return this.find({ active: { $ne: false } });
};
//Instanc method is available on all documents of a given collection
userSchema.methods.correctPassword = function (
// this.password not availble because we disabled select
candidatePassword, userPassword) {
    return __awaiter(this, void 0, void 0, function* () {
        return yield bcryptjs_1.default.compare(candidatePassword, userPassword);
    });
};
userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
    if (this.passwordChangedAt) {
        const changedTimestamp = parseInt((this.passwordChangedAt.getTime() / 1000).toString(), // Convert number to string
        10);
        return JWTTimestamp < changedTimestamp;
    }
    // False means NOT changed
    return false;
};
userSchema.methods.createPasswordResetToken = function () {
    //don't store in db as plaintext as if a bad actor gains db access they can use it to reset the user's password
    const resetToken = crypto_1.default.randomBytes(32).toString('hex');
    // use sha256 algo to encrypt resetToken and store as hex again
    this.passwordResetToken = crypto_1.default
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
    this.find({
        active: { $ne: false },
    });
    next();
});
userSchema.pre('save', function (next) {
    return __awaiter(this, void 0, void 0, function* () {
        //Only run this function if the password was modified
        if (!this.isModified('password'))
            return next();
        //Hash the password with a cost of 12, the higher the more CPU intensive the operation (duration)
        this.password = yield bcryptjs_1.default.hash(this.password, 12);
        // Delete the password confirm field
        // It's a required input not that it's required to be persisted to the db, thats why we can remove it here
        this.passwordConfirm = '';
        this.passwordChangedAt = new Date(Date.now());
    });
});
userSchema.pre('save', function (next) {
    return __awaiter(this, void 0, void 0, function* () {
        if (!this.isModified('password') || this.isNew)
            return next();
        // sometimes takes longer to save in db than to send jwt so it makes it look like password was changed after jwt createdAt, so we subtract 1s
        this.passwordChangedAt = new Date(Date.now() - 1000);
        next();
    });
});
const User = mongoose_1.default.model('User', userSchema);
exports.default = User;
