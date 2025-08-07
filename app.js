const express = require('express');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const cors = require('cors');
const compression = require('compression');

const AppError = require('./utils/appError');
const globalErrorHandler = require('./controllers/errorController');
const userRoutes = require('./routes/userRoutes');

const app = express();

// 1) MIDDLEWARES
app.use(cors());

// Set security HTTP headers
app.use(helmet());

app.use(compression());

if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

const limiter = rateLimit({
  limit: 5,
  windowMs: 15 * 60 * 1000,
  message: 'لقد تجاوزت عدد المحاولات المسموح بها، حاول لاحقًا ',
});

app.use('/api/v1/users/login', limiter); // apply limiter to login endpoint

// Putting all data in the body into request obj to read it
app.use(express.json());

// Data sanitization against NoSQL query injection comments
app.use(mongoSanitize());

// 3) ROUTES
app.use('/api/v1/users', userRoutes);

// Handler for Unhandled Routes
app.all('*', (req, res, next) => {
  next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404));
});

// Global Error Handler
app.use(globalErrorHandler);

module.exports = app;
