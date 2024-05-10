"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const userController_1 = __importDefault(require("./../controllers/userController"));
const authController_1 = __importDefault(require("./../controllers/authController"));
const userModel_1 = require("../models/userModel");
const router = express_1.default.Router();
router.post('/signup', authController_1.default.signup);
router.post('/login', authController_1.default.login);
router.get('/logout', authController_1.default.logout);
router.post('/forgotPassword', authController_1.default.forgotPassword);
router.patch('/resetPassword/:token', authController_1.default.resetPassword);
//Protect all routes after this point
router.use(authController_1.default.protect);
router.patch('/updateMyPassword/', authController_1.default.updatePassword);
router.get('/me', userController_1.default.getMe, userController_1.default.getUser);
router.patch('/updateMe', userController_1.default.uploadUserPhoto, userController_1.default.resizeUserPhoto, userController_1.default.updateMe);
router.delete('/deleteMe', userController_1.default.deleteMe);
router.use(authController_1.default.restrictTo(userModel_1.Role.ADMIN));
router.route('/').get(userController_1.default.getAllUsers);
router
    .route('/:id')
    .get(userController_1.default.getUser)
    .patch(userController_1.default.updateUser)
    .delete(userController_1.default.deleteUser);
exports.default = router;
