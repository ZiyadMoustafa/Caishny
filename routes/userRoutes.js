const express = require('express');

const authController = require('../controllers/authController');

const router = express.Router();

router.post(
  '/signup',
  authController.uploadPhoto,
  authController.resizePhotosAndUpload,
  authController.signup,
);
router.post('/verifyEmail', authController.emailVerification);
router.post('/login', authController.login);
router.post('/resendCode', authController.resendVerificationCode);
router.post('/forgetPassword', authController.forgetPassword);
router.post('/verifyPassCode', authController.verifyPassResetCode);
router.patch('/resetPassword/:id', authController.resetPassword);
router.get('/logout', authController.logout);

router.use(authController.protect);

module.exports = router;
