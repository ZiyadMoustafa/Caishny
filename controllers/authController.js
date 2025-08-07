const fs = require('fs');
const path = require('path');
const { promisify } = require('util');
const multer = require('multer');
const sharp = require('sharp');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const FileType = require('file-type');
const AppError = require('../utils/appError');
const catchAsync = require('../utils/catchAsync');
const sendEmail = require('../utils/email');
const cloud = require('../utils/cloud');

const User = require('../models/userModel');

// ***********************************************************************************
const multerStorage = multer.memoryStorage();

// File filter to allow only images
const multerFilter = (req, file, cb) => {
  if (file.mimetype.startsWith('image')) {
    cb(null, true);
  } else {
    cb(new AppError('Only images are allowed!', 404), false);
  }
};

// Multer configuration
const upload = multer({
  storage: multerStorage,
  fileFilter: multerFilter,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB
    files: 3, // فقط 3 صور
  },
});

exports.uploadPhoto = upload.array('photos');

const uploadToCloudinary = (buffer, filename, folderPath) =>
  new Promise((resolve, reject) => {
    const uploadStream = cloud.uploader.upload_stream(
      {
        folder: folderPath,
        public_id: filename,
        resource_type: 'image',
      },
      (error, result) => {
        if (error) {
          reject(error);
        } else {
          resolve(result);
        }
      },
    );
    uploadStream.end(buffer);
  });

// Middleware to Process and Upload Image to Cloudinary
exports.resizePhotosAndUpload = catchAsync(async (req, res, next) => {
  if (!req.files || req.files.length === 0) return next();

  const { fullName } = req.body;

  const folderPath = `Caishny/Drivers${fullName}`;

  const uploadPromises = req.files.map(async (file) => {
    // 1) تحقق من نوع الملف عن طريق تحليل محتوي الملف
    const fileType = await FileType.fromBuffer(file.buffer);
    if (!fileType || !['image/jpeg', 'image/png'].includes(fileType.mime)) {
      throw new AppError('نوع الصورة غير مدعوم', 400);
    }

    // 2) نظف الصورة
    const imageBuffer = await sharp(file.buffer)
      .toFormat('jpeg')
      .jpeg({ quality: 90 })
      .withMetadata({ exif: false })
      .toBuffer();

    // 3) اسم عشوائي آمن
    const uniqueFileName = uuidv4();

    // 4) ارفعها على Cloudinary
    const result = await uploadToCloudinary(
      imageBuffer,
      uniqueFileName,
      folderPath,
    );

    return result.secure_url;
  });

  // ⏳ انتظر كل عمليات الرفع تخلص
  const uploadedImages = await Promise.all(uploadPromises);

  // Add image URLs to req.body
  req.body.photos = uploadedImages;

  next();
});
// ***********************************************************************************

// create token
const signToken = (id, role) =>
  jwt.sign({ userId: id, role: role }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });

// send token in cookie
const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id, user.role);

  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000,
    ),
    httpOnly: true,
    sameSite: 'None',
  };

  if (process.env.NODE_ENV === 'production') cookieOptions.secure = true;

  res.cookie('jwt', token, cookieOptions);

  // remove password from output
  user.password = undefined;

  res.status(statusCode).json({
    status: 'success',
    data: {
      user,
    },
  });
};

exports.signup = catchAsync(async (req, res, next) => {
  const existUser = await User.findOne({ email: req.body.email });
  if (existUser) {
    return next(new AppError('المستخدم موجود بالفعل', 400));
  }

  // 1) create an account
  const user = await User.create(req.body);

  // 2) generate the random code (5 digit)
  const VerificationCode = user.createEmailVerificationCode();
  await user.save({ validateBeforeSave: false });

  // 3) send email to user
  try {
    let htmlTemplate = fs.readFileSync(
      path.join(__dirname, '../views/emailTemplate.html'),
      'utf8',
    );

    // Replace placeholders with actual values
    htmlTemplate = htmlTemplate.replace(
      '{{USER}}',
      req.body.fullName.split(' ')[0],
    );
    htmlTemplate = htmlTemplate.replace(
      '{{reason}}',
      `verify your email address`,
    );
    htmlTemplate = htmlTemplate.replace('{{OTP}}', VerificationCode);

    await sendEmail({
      email: user.email,
      subject: 'Email Verification',
      htmlTemplate,
    });

    res.status(200).json({
      status: 'success',
      message:
        'تم انشاء الحساب بنجاح وارسال رمز التحقق. تفقد حسابك لاتمام عملية تسجيل الدخول',
    });
  } catch (err) {
    user.emailVerificationCode = undefined;
    user.VerificationCodeExpires = undefined;

    await user.save({ validateBeforeSave: false });

    return next(new AppError(err, 500));
  }
});

exports.emailVerification = catchAsync(async (req, res, next) => {
  const { verificationCode } = req.body;

  const hashedverificationCode = crypto
    .createHash('sha256')
    .update(verificationCode)
    .digest('hex');

  const user = await User.findOne({
    emailVerificationCode: hashedverificationCode,
    VerificationCodeExpires: { $gt: Date.now() },
  });

  if (!user) return next(new AppError('رمز التحقق غير صحيح أو انتهي', 404));

  user.active = true;
  user.emailVerificationCode = undefined;
  user.VerificationCodeExpires = undefined;
  await user.save({ validateBeforeSave: false });

  res.status(200).json({
    status: 'success',
    message: 'تم الانتهاء من عملية التحقق بنجاح , تستطيع تسجيل الدخول الان',
  });
});

exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  // 1) check if email and passowrd exist
  if (!email || !password) {
    return next(
      new AppError('من فضلك ادخل البريد الالكتروني وكلمة المرور', 400),
    );
  }

  // 2) check if client exist and password correct
  const user = await User.findOne({ email }).select('+password');

  if (
    !user ||
    !(await user.correctPassword(req.body.password, user.password))
  ) {
    return next(
      new AppError('البريد الالكتروني أو كلمة المرور غير صحيحة', 401),
    );
  }

  // 3) check account type
  if (!user.active) {
    return next(new AppError(' لا تستطيع تسجيل الدخول , حسابك غير مُفعل', 400));
  }

  // 4) if everything is ok , send response

  createSendToken(user, 200, res);
});

exports.resendVerificationCode = catchAsync(async (req, res, next) => {
  const { email } = req.body;

  const user = await User.findOne({ email });

  if (!user) {
    return next(new AppError('هذا البريد الإلكتروني غير مسجل.', 404));
  }

  if (user.active) {
    return next(new AppError('الحساب مفعل بالفعل.', 400));
  }

  // Generate new code
  const verificationCode = user.createEmailVerificationCode();
  if (!verificationCode.allowed) {
    return next(
      new AppError(
        'تم إرسال كود بالفعل. برجاء الانتظار حتى انتهاء صلاحية الكود الحالي.',
        429,
      ),
    );
  }
  await user.save({ validateBeforeSave: false });

  // Read email template
  let htmlTemplate = fs.readFileSync(
    path.join(__dirname, '../views/emailTemplate.html'),
    'utf8',
  );

  htmlTemplate = htmlTemplate.replace('{{USER}}', user.username);
  htmlTemplate = htmlTemplate.replace(
    '{{reason}}',
    `verify your email address`,
  );
  htmlTemplate = htmlTemplate.replace('{{OTP}}', verificationCode);

  await sendEmail({
    email: user.email,
    subject: 'Email Verification - Resend',
    htmlTemplate,
  });

  res.status(200).json({
    status: 'success',
    message: 'تم إعادة إرسال رمز التحقق إلى بريدك الإلكتروني.',
  });
});

exports.forgetPassword = catchAsync(async (req, res, next) => {
  // 1) get user
  const user = await User.findOne({ email: req.body.email });
  if (!user) return next(new AppError('المستخدم غير موجود', 404));

  // 2) generate the random reset code (5 digit)
  const resetCode = user.createPasswordResetCode();

  if (!resetCode.allowed) {
    return next(
      new AppError(
        'تم إرسال كود بالفعل. برجاء الانتظار حتى انتهاء صلاحية الكود الحالي.',
        429,
      ),
    );
  }

  await user.save({ validateBeforeSave: false });

  // 3) send email to user
  try {
    let htmlTemplate = fs.readFileSync(
      path.join(__dirname, '../views/emailTemplate.html'),
      'utf8',
    );

    // Replace placeholders with actual values

    htmlTemplate = htmlTemplate.replace('{{USER}}', user.username);

    htmlTemplate = htmlTemplate.replace('{{reason}}', `reset your password`);

    htmlTemplate = htmlTemplate.replace('{{OTP}}', resetCode);
    await sendEmail({
      email: user.email,
      subject: 'Reset Password',
      htmlTemplate,
    });

    res.status(200).json({
      status: 'success',
      message: 'تم ارسال البريد الالكتروني بنجاح , تحقق من بريدك الالكتروني',
    });
  } catch (err) {
    user.passwordResetCode = undefined;
    user.passwordResetExpires = undefined;
    user.passwordResetVerified = undefined;

    await user.save({ validateBeforeSave: false });

    return next(new AppError(err, 500));
  }
});

exports.verifyPassResetCode = catchAsync(async (req, res, next) => {
  const { resetCode } = req.body;

  const hashedResetCode = crypto
    .createHash('sha256')
    .update(resetCode)
    .digest('hex');

  const user = await User.findOne({
    passwordResetCode: hashedResetCode,
    passwordResetExpires: { $gt: Date.now() },
  });

  if (!user)
    return next(new AppError('رمز اعادة التعيين غير صحيح أو انتهي', 404));

  user.passwordResetVerified = true;
  await user.save({ validateBeforeSave: false });

  res.status(200).json({
    status: 'success',
    userId: user._id,
  });
});

exports.resetPassword = catchAsync(async (req, res, next) => {
  // 1) Get and find user based on id
  const user = await User.findById(req.params.id);

  if (!user) return next(new AppError('لا يوجد مستخدم', 404));

  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  user.passwordResetCode = undefined;
  user.passwordResetExpires = undefined;
  user.passwordResetVerified = undefined;
  await user.save();

  res.status(200).json({
    status: 'success',
    message: 'تم تغيير كلمة المرور بنجاح',
  });
});

exports.logout = (req, res) => {
  res.cookie('jwt', 'loggedout', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true,
  });
  res.status(200).json({ status: 'success' });
};

// function for Authoraization
exports.restrictTo =
  (...roles) =>
  (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(new AppError('ليس لديك الصلاحيات للقيام بهذا الاجراء', 403));
    }
    next();
  };

exports.protect = catchAsync(async (req, res, next) => {
  // 1) Get token
  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies) {
    token = req.cookies.jwt;
  }
  if (!token) {
    return next(
      new AppError(
        'لم تقم بتسجيل الدخول، يرجى تسجيل الدخول للقيام بهذا الاجراء',
        401,
      ),
    );
  }
  // 2) Verification token
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  // 3) Check if user still exist
  const currentUser = await User.findById(decoded.userId);
  if (!currentUser) return next(new AppError('هذا المستخدم لم يعد موجود', 400));

  // 4) check if password chaged after create token
  if (currentUser.changePasswordAfter(decoded.iat))
    return next(
      new AppError('تم تغيير كلمة المرور من قريب! , سجل دخول مرة أخري', 401),
    );

  req.user = currentUser;
  next();
});

exports.updateMyPassword = catchAsync(async (req, res, next) => {
  // 1) Get user
  const user = await User.findById(req.user.id).select('+password');
  if (!user) {
    return next(new AppError('المستخدم لم يعد موجود', 404));
  }

  // 2) check current password is correct
  const isMatch = await user.correctPassword(
    req.body.currentPassword,
    user.password,
  );
  if (!isMatch)
    return next(
      new AppError(
        'كلمة المرور الذي قمت بادخالها غير مطابقة لكلمة المرور الاصلية',
        404,
      ),
    );

  // 3) if OK , change password
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;

  await user.save();

  // continue using the app
  createSendToken(user, 200, res);
});
