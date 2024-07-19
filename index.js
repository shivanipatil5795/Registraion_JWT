const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { check, validationResult } = require('express-validator');

const app = express();

app.use(bodyParser.json());
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

mongoose.connect('mongodb://localhost:27017/userdb', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => {
  console.log('Connected to Database');
}).catch((err) => {
  console.error('Error in Connecting to Database', err);
});

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  phno: String,
  username: String,
  password: String,
  role: { type: String, default: 'user' }
});

const User = mongoose.model('User', userSchema);

const JWT_SECRET = 'test@123';

app.post("/sign_up", [
  check('name').notEmpty().withMessage('Name is required'),
  check('email').isEmail().withMessage('Email is not valid'),
  check('phno').isMobilePhone().withMessage('Phone number is not valid'),
  check('username').notEmpty().withMessage('Username is required'),
  check('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { name, email, phno, username, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const role = email.endsWith('@example.com') ? 'admin' : 'user';

    console.log(`Debugging: Email: ${email}, Role: ${role}`);

    const data = {
      name: name,
      email: email,
      phno: phno,
      username: username,
      password: hashedPassword,
      role: role
    };

    const user = new User(data);
    await user.save();

    console.log("Record Inserted Successfully");
    return res.redirect('/signup_successful.html');
  } catch (err) {
    console.error(err);
    return res.status(500).send("Error registering user");
  }
});

app.post("/login", [
  check('username').notEmpty().withMessage('Username is required'),
  check('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username: username });
    if (!user) {
      return res.status(400).send('User not found');
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).send('Invalid credentials');
    }

    const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });

    // Log the token for debugging purposes
    console.log(`Generated Token: ${token}`);

    res.cookie('token', token, { httpOnly: true, secure: false, sameSite: 'strict' });

    // Log cookie setting for debugging purposes
    console.log('Cookie set successfully:', req.cookies.token);

    if (user.role === 'admin') {
      return res.redirect('/admin_dashboard.html');
    } else {
      return res.redirect('/user_dashboard.html');
    }
  } catch (err) {
    console.error(err);
    return res.status(500).send("Server Error");
  }
});

const authenticateJWT = (req, res, next) => {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).send('Access Denied');
  }

  try {
    const verified = jwt.verify(token, JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(400).send('Invalid Token');
  }
};

app.get("/", (req, res) => {
  res.set({
    "Allow-access-Allow-Origin": '*'
  });
  return res.redirect('/index.html');
});

app.get("/user_dashboard", authenticateJWT, (req, res) => {
  if (req.user.role !== 'user') {
    return res.status(403).send('Access Denied');
  }
  res.sendFile(__dirname + '/public/user_dashboard.html');
});

app.get("/admin_dashboard", authenticateJWT, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).send('Access Denied');
  }
  res.sendFile(__dirname + '/public/admin_dashboard.html');
});

app.get('/logout', (req, res) => {
  res.clearCookie('token');
  return res.redirect('/');
});

app.listen(3000, () => {
  console.log("Listening on port 3000");
});
