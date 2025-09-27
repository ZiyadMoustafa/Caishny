const AppError = require('../utils/appError');
const catchAsync = require('../utils/catchAsync');
const multer = require('multer');
const sharp = require('sharp');
const { v4: uuidv4 } = require('uuid');
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
    fileSize: 2 * 1024 * 1024,
    files: 1,
  },
});

exports.uploadPhoto = upload.single('profilePhoto');

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
  const { fileTypeFromBuffer } = await import('file-type');

  if (!req.file) return next();

  const folderPath = `Caishny/ProfilePhotos`;

  const fileType = await fileTypeFromBuffer(req.file.buffer);
  if (!fileType || !['image/jpeg', 'image/png'].includes(fileType.mime)) {
    throw new AppError('نوع الصورة غير مدعوم', 400);
  }

  const imageBuffer = await sharp(req.file.buffer)
    .toFormat('jpeg')
    .jpeg({ quality: 70 })
    .toBuffer();

  const uniqueFileName = uuidv4();

  const result = await uploadToCloudinary(
    imageBuffer,
    uniqueFileName,
    folderPath,
  );

  // Add image URL to req.body
  req.body.profilePhoto = result.secure_url;

  next();
});

// ***********************************************************************************
exports.getUser = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.user.id);

  res.status(200).json({
    status: 'success',
    data: {
      user,
    },
  });
});

exports.updateUser = catchAsync(async (req, res, next) => {
  const updateduser = await User.findByIdAndUpdate(req.user.id, req.body, {
    new: true,
  });

  await updateduser.save({ validateBeforeSave: false });

  res.status(200).json({
    status: 'success',
    message: 'updated successfully',
    data: {
      updateduser,
    },
  });
});

exports.deleteMe = catchAsync(async (req, res, next) => {
  await User.findByIdAndUpdate(req.user.id, { active: false });

  res.cookie('jwt', 'loggedout', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true,
  });

  res.status(204).json({
    status: 'success',
    data: null,
  });
});
