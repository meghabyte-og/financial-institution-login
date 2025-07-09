const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");
const axios = require("axios");

const router = express.Router();
const User = require("../models/user");
// router.post(
//   "/register",
//   [
//     body("username").isLength({ min: 3 }),
//     body("email").isEmail(),
//     body("password").isLength({ min: 8 }),
//   ],
router.post(
  "/register",
  [
    body("username").isLength({ min: 3 }),
    body("email").isEmail(),
    body("password").matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$/)
      .withMessage("Password must include uppercase, lowercase, number, and be 8+ chars"),
  ],

  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });

    const { username, email, password } = req.body;

    try {
      const existing = await User.findOne({ email });
      if (existing)
        return res.status(400).json({ message: "Email already in use" });

      const hashed = await bcrypt.hash(password, 10);
      const user = await User.create({ username, email, password: hashed });

      const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
        expiresIn: "2h",
      });
      res
      .cookie("token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
      }) 
  // .json({ user: { username, email }, token });

  //     res
  //       .cookie("token", token, { httpOnly: true, secure: false })
  //       .json({ user: { username, email }, token });
    } catch (err) {
      res.status(500).json({ message: "Server error", error: err.message });
    }
  }
);

router.post(
  "/login",
  [body("email").isEmail(), body("password").exists()],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });

    const { email, password } = req.body;

    try {
      const user = await User.findOne({ email });
      if (!user) return res.status(401).json({ message: "Invalid credentials" });

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return res.status(401).json({ message: "Invalid credentials" });

      const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
        expiresIn: "2h",
      });

      res
        .cookie("token", token, { httpOnly: true, secure: false })
        .json({ user: { username: user.username, email: user.email }, token });
    } catch (err) {
      res.status(500).json({ message: "Server error", error: err.message });
    }
  }
);

// Verify reCAPTCHA
router.post("/verify-recaptcha", async (req, res) => {
  const { token } = req.body;

  try {
    const response = await axios.post(
      `https://www.google.com/recaptcha/api/siteverify?secret=${process.env.RECAPTCHA_SECRET_KEY}&response=${token}`
    );

    if (!response.data.success) {
      return res.status(400).json({ message: "reCAPTCHA failed" });
    }

    res.status(200).json({ message: "reCAPTCHA verified" });
  } catch (err) {
    res.status(500).json({ message: "reCAPTCHA error", error: err.message });
  }
});

module.exports = router;
