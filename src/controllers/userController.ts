import User, { IUser } from '../models/userModel';
import AsyncErrorHandler from '../utils/AsyncErrorHandler';
import AppError from '../utils/AppError';
import { getAll, getOne, deleteOne, updateOne } from '../utils/handlerFactory';
import { Request, Response, NextFunction } from 'express';
// use to handle multi-part form data, form encoding to upload files from a form upload images
import multer, { FileFilterCallback } from 'multer';
import sharp from 'sharp';
import { AuthenticatedRequest } from './authController';

const getUserIdFromProtectedRequest = (req: Request): string => {
  const authenticatedRequest = req as AuthenticatedRequest;
  return String(authenticatedRequest.user._id);
};

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

const uploadUserPhoto = upload.single('avatar');

const resizeUserPhoto = AsyncErrorHandler(async (req, _res, next) => {
  if (!req.file) return next();

  req.file.filename = `user-${(req as AuthenticatedRequest).user._id}-${Date.now()}.jpeg`;

  await sharp(req.file.buffer)
    .resize(500, 500)
    .toFormat('jpeg')
    .jpeg({ quality: 90 })
    .toFile(`public/img/users/${req.file.filename}`);

  next();
});

const updateMe = AsyncErrorHandler(async (req, res, next) => {
  // 1) Create error if user POSTs password data
  if (req.body.password || req.body.passwordConfirm) {
    return next(new AppError('This route is not for password updates', 400));
  }

  // 2) Update user document
  const { name, email } = req.body;
  const user = await User.findById(getUserIdFromProtectedRequest(req));

  if (!user) return next(new AppError('User to update not found', 404));

  if (name) user.name = name;
  if (email) user.email = email;

  if (req.file) user.avatar = req.file.filename;

  const updatedUser = await user.save({ validateModifiedOnly: true });

  res.status(200).json({
    status: 'success',
    data: {
      user: updatedUser,
    },
  });
});

// User can't delete their own account. It's just set to inactive. Security practice
const deleteMe = AsyncErrorHandler(async (req, res, next) => {
  const id = getUserIdFromProtectedRequest(req);

  await User.findByIdAndUpdate(id, { active: false });
  res.status(204).json({
    status: 'success',
    data: null,
  });
});

const getMe = (req: Request, res: Response, next: NextFunction) => {
  req.params.id = getUserIdFromProtectedRequest(req);
  next();
};

const getAllUsers = getAll(User);
const getUser = getOne(User);
//DO NOT UPDATE PASSWORDS WITH THIS
const updateUser = updateOne(User);
const deleteUser = deleteOne(User);

export default {
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
