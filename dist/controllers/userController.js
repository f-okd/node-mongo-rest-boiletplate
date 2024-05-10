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
const userModel_1 = __importDefault(require("../models/userModel"));
const AsyncErrorHandler_1 = __importDefault(require("../utils/AsyncErrorHandler"));
const AppError_1 = __importDefault(require("../utils/AppError"));
const handlerFactory_1 = require("../utils/handlerFactory");
// use to handle multi-part form data, form encoding to upload files from a form upload images
const multer_1 = __importDefault(require("multer"));
const sharp_1 = __importDefault(require("sharp"));
const getUserIdFromProtectedRequest = (req) => {
    const authenticatedRequest = req;
    return String(authenticatedRequest.user._id);
};
const getUserFromProtectedRequest = (req) => {
    const authenticatedRequest = req;
    return authenticatedRequest.user;
};
// const multerStorage = multer.diskStorage({
//   destination: (req, file, cb) => {
//     cb(null, 'public/img/users');
//   },
//   filename: (req, file, cb) => {
//     const ext = file.mimetype.split('/')[1];
//     cb(null, `user-${req.user._id}-${Date.now()}.${ext}`);
//   },
// });
//Image stored as buffer, which is available at req.file.buffer, dont have to write file to disk then read it again
const multerStorage = multer_1.default.memoryStorage();
const multerFilter = (req, file, cb) => {
    if (file.mimetype.startsWith('image')) {
        cb(null, true);
    }
    else {
        cb(new AppError_1.default('Please only upload Images', 400));
    }
};
//dest: where to save images we want to upload
const upload = (0, multer_1.default)({
    storage: multerStorage,
    fileFilter: multerFilter,
});
//'single' field in form that will contain image to upload, singlE:1 file.
// Will copy file and put in destination and put information about it on the request
const uploadUserPhoto = upload.single('photo');
const resizeUserPhoto = (0, AsyncErrorHandler_1.default)((req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    if (!req.file)
        return next();
    req.file.filename = `user-${req.user._id}-${Date.now()}.jpeg`;
    yield (0, sharp_1.default)(req.file.buffer)
        .resize(500, 500)
        .toFormat('jpeg')
        .jpeg({ quality: 90 })
        .toFile(`public/img/users/${req.file.filename}`);
    next();
}));
const updateMe = (0, AsyncErrorHandler_1.default)((req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    // 1) Create error if user POSTs password data
    if (req.body.password || req.body.passwordConfirm) {
        return next(new AppError_1.default('This route is not for password updates', 400));
    }
    // 2) Update user document
    const { name, email } = req.body;
    const user = yield userModel_1.default.findById(getUserIdFromProtectedRequest(req));
    if (!user)
        return next(new AppError_1.default('User to update not found', 404));
    if (name)
        user.name = name;
    if (email)
        user.email = email;
    if (req.file)
        user.avatar = req.file.filename;
    const updatedUser = yield user.save({ validateModifiedOnly: true });
    res.status(200).json({
        status: 'success',
        data: {
            user: updatedUser,
        },
    });
}));
const deleteMe = (0, AsyncErrorHandler_1.default)((req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    const id = getUserIdFromProtectedRequest(req);
    yield userModel_1.default.findByIdAndUpdate(id, { active: false });
    res.status(204).json({
        status: 'success',
        data: null,
    });
}));
const getMe = (req, res, next) => {
    req.params.id = getUserIdFromProtectedRequest(req);
    next();
};
const getAllUsers = (0, handlerFactory_1.getAll)(userModel_1.default);
const getUser = (0, handlerFactory_1.getOne)(userModel_1.default);
//DO NOT UPDATE PASSWORDS WITH THIS
const updateUser = (0, handlerFactory_1.updateOne)(userModel_1.default);
const deleteUser = (0, handlerFactory_1.deleteOne)(userModel_1.default);
exports.default = {
    getAllUsers,
    getUser,
    updateUser,
    deleteUser,
    getMe,
    deleteMe,
    updateMe,
    uploadUserPhoto,
    resizeUserPhoto,
};
