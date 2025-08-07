const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const _ = require('lodash');

const userSchema = new mongoose.Schema(
  {
    fullName: {
      type: String,
      required: [true, 'Please enter your full name'],
      trim: true,
    },
    username: { type: String },
    email: {
      type: String,
      required: true,
      validate: [validator.isEmail, 'Please enter a valid email'],
      unique: true,
      trim: true,
      lowercase: true,
    },
    mobileNumber: {
      type: String,
      required: [true, 'Mobile number is required'],
      unique: true,
      validate: {
        validator: function (el) {
          return validator.isMobilePhone(el, 'ar-EG'); // "ar-EG" only Egyptian numbers are allowed
        },
        message: 'Invalid Egyptian phone number format',
      },
    },
    password: {
      type: String,
      required: [true, 'fill password field'],
      minlength: [8, 'Password must be above 8 characters'],
      maxlength: [20, 'Password must be below 20 characters'],
      select: false,
    },
    passwordConfirm: {
      type: String,
      required: [true, 'fill passwordConfirm field'],
      validate: {
        validator: function (el) {
          return el === this.password;
        },
        message: 'Passwords are not the same',
      },
    },
    location: {
      type: {
        type: String,
        enum: ['Point'],
        default: 'Point',
      },
      coordinates: {
        type: [Number],
        required: true,
      },
    },
    role: {
      type: String,
      required: true,
      enum: ['مستخدم', 'سائق', 'ادمن'],
    },
    active: {
      type: Boolean,
      default: false,
    },
    createdAt: {
      type: Date,
      default: Date.now,
    },
    photos: [String],
    passwordChangedAt: {
      type: Date,
    },
    emailVerificationCode: String,
    VerificationCodeExpires: Date,
    passwordResetCode: String,
    passwordResetExpires: Date,
    passwordResetVerified: Boolean,
  },
  {
    toJSON: {
      transform: function (doc, ret) {
        return _.omit(ret, ['__v', 'password', 'passwordChangedAt']);
      },
    },
  },
);

userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();

  this.password = await bcrypt.hash(this.password, 12);

  this.passwordConfirm = undefined;
});

userSchema.pre('save', async function (next) {
  if (!this.isModified('password') || this.isNew) return next();

  this.passwordChangedAt = Date.now() - 1000;
});

userSchema.pre('save', function (next) {
  this.username = this.fullName.split(' ')[0];
  next();
});

userSchema.methods.correctPassword = async function (
  bodyPassword,
  userPassword,
) {
  return await bcrypt.compare(bodyPassword, userPassword);
};
userSchema.methods.changePasswordAfter = function (JWTTimestamps) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10,
    );

    return JWTTimestamps < changedTimestamp;
  }

  return false;
};

userSchema.methods.createPasswordResetCode = function () {
  if (this.passwordResetExpires && this.passwordResetExpires > Date.now()) {
    return { allowed: false };
  }

  const resetCode = Math.floor(10000 + Math.random() * 90000).toString();

  this.passwordResetCode = crypto
    .createHash('sha256')
    .update(resetCode)
    .digest('hex');

  this.passwordResetExpires = Date.now() + 10 * 60 * 1000;
  this.passwordResetVerified = false;

  return resetCode;
};

userSchema.methods.createEmailVerificationCode = function () {
  if (
    this.VerificationCodeExpires &&
    this.VerificationCodeExpires > Date.now()
  ) {
    return { allowed: false };
  }

  const verifyCode = Math.floor(10000 + Math.random() * 90000).toString();

  this.emailVerificationCode = crypto
    .createHash('sha256')
    .update(verifyCode)
    .digest('hex');

  this.VerificationCodeExpires = Date.now() + 10 * 60 * 1000;

  return verifyCode;
};

// Index location for geospatial queries
userSchema.index({ location: '2dsphere' });

const User = mongoose.model('User', userSchema);
module.exports = User;
