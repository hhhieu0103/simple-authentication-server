var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var cors = require('cors');
var session = require('express-session');
var mongoStore = require('connect-mongo');

var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');
var authenticationRouter = require('./routes/authentication')

var corsOptions = {
  origin: 'http://localhost:4200',
  credentials: true,
}

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(cors(corsOptions))

app.use(session({
  name: 'simple-authentication',
  secret: 'simple-authentication',
  resave: false,
  saveUninitialized: false,
  store: mongoStore.create({
    mongoUrl: 'mongodb://localhost:27017/simple-authentication'
  }),
  cookie: {
    secure: false,
    httpOnly: true,
    maxAge: 1000 * 20
  },
}));

app.use('/', indexRouter);
app.use('/users', usersRouter);
app.use('/authentication', authenticationRouter);

// catch 404 and forward to error handler
app.use(function (req, res, next) {
  next(createError(404));
});

// error handler
app.use(function (err, req, res, next) {
  // set locals, only providing error in development
  if (req.app.get('env') === 'development') {
    res.message = err.message;
    res.error = err;
  }

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
