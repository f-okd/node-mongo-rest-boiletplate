import express from 'express';
import userController from './../controllers/userController';
import authController from './../controllers/authController';
import { Role } from '../models/userModel';

const router = express.Router();

router.post('/signup', authController.signup);
router.post('/login', authController.login);
router.get('/logout', authController.logout);

router.post('/forgotPassword', authController.forgotPassword);
router.patch('/resetPassword/:token', authController.resetPassword);

//Protect all routes after this point
router.use(authController.protect);

router.patch('/updateMyPassword/', authController.updatePassword);
router.get('/me', userController.getMe, userController.getUser);

router.patch(
  '/updateMe',
  userController.uploadUserPhoto,
  userController.resizeUserPhoto,
  userController.updateMe,
);
router.delete('/deleteMe', userController.deleteMe);

router.use(authController.restrictTo(Role.ADMIN));

router.route('/').get(userController.getAllUsers);
router
  .route('/:id')
  .get(userController.getUser)
  .patch(userController.updateUser)
  .delete(userController.deleteUser);

export default router;
