// Basic backend system for user signup, login, OTP verification, and refresh token logic

const express = require("express");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const app = express();
const PORT = 3000;

app.use(express.json());
app.use(cookieParser());

// In-memory storage
let users = [];
let otps = {}; // { email_or_mobile: { otp, expiresAt } }
let refreshTokens = {}; // { userId: refreshToken }

const SECRET = "access-secret-key";
const REFRESH_SECRET = "refresh-secret-key";

// Utility functions
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();
const generateToken = (user) => jwt.sign({ id: user.id }, SECRET, { expiresIn: '15m' });
const generateRefreshToken = (user) => jwt.sign({ id: user.id }, REFRESH_SECRET, { expiresIn: '7d' });
const hashPassword = (password) => crypto.createHash('sha256').update(password).digest('hex');

const authMiddleware = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ message: 'Unauthorized' });
  try {
    const data = jwt.verify(token, SECRET);
    req.user = data;
    next();
  } catch {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
};

// Routes

// 1. Signup
app.post("/signup", (req, res) => {
  const { name, email, mobile, password } = req.body;
  if (!email || !password || !name || !mobile)
    return res.status(400).json({ message: "All fields are required" });

  const existingUser = users.find(u => u.email === email || u.mobile === mobile);
  if (existingUser)
    return res.status(409).json({ message: "User already exists" });

  const user = {
    id: crypto.randomUUID(),
    name,
    email,
    mobile,
    password: hashPassword(password),
    verified: false
  };

  users.push(user);

  const otp = generateOTP();
  otps[email] = { otp, expiresAt: Date.now() + 5 * 60 * 1000 }; // expires in 5 mins
  console.log(`OTP for ${email}: ${otp}`); // Simulate sending OTP

  res.status(201).json({ message: "User registered. OTP sent to email." });
});

// 2. Login
app.post("/login", (req, res) => {
  const { email, mobile, password } = req.body;
  const identifier = email || mobile;
  const user = users.find(u => u.email === identifier || u.mobile === identifier);

  if (!user || user.password !== hashPassword(password))
    return res.status(401).json({ message: "Invalid credentials" });

  if (!user.verified)
    return res.status(403).json({ message: "User not verified" });

  const token = generateToken(user);
  const refreshToken = generateRefreshToken(user);
  refreshTokens[user.id] = refreshToken;

  res.cookie("token", token, { httpOnly: true });
  res.cookie("refreshToken", refreshToken, { httpOnly: true });
  res.json({ message: "Login successful" });
});

// 3. Verify OTP
app.post("/verify-otp", (req, res) => {
  const { identifier, otp } = req.body;
  const record = otps[identifier];
  if (!record) return res.status(400).json({ message: "No OTP found" });

  if (record.expiresAt < Date.now()) return res.status(400).json({ message: "OTP expired" });
  if (record.otp !== otp) return res.status(400).json({ message: "Invalid OTP" });

  const user = users.find(u => u.email === identifier || u.mobile === identifier);
  if (user) user.verified = true;
  delete otps[identifier];
  res.json({ message: "OTP verified, user is now active." });
});

// 4. Refresh token
app.post("/refresh-token", (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) return res.status(401).json({ message: "No refresh token" });

  try {
    const decoded = jwt.verify(refreshToken, REFRESH_SECRET);
    const userId = decoded.id;

    if (refreshTokens[userId] !== refreshToken)
      return res.status(403).json({ message: "Invalid refresh token" });

    const newToken = generateToken({ id: userId });
    res.cookie("token", newToken, { httpOnly: true });
    res.json({ message: "Token refreshed" });
  } catch {
    return res.status(403).json({ message: "Invalid or expired refresh token" });
  }
});

// Protected route example
app.get("/protected", authMiddleware, (req, res) => {
  res.json({ message: `Hello user ${req.user.id}, you're authorized!` });
});

app.get("/", (req, res) => {
  res.send("Welcome to the Auth Backend!");
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
