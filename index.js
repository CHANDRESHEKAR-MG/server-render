const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const User = require("./models/User");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const bcrypt = require("bcryptjs");

const app = express();
app.use(express.json());
app.use(cors());

// Connect the Database
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("Database Connection Established"))
  .catch((err) => {
    console.error("Database Connection Error:", err);
  });

// Sign-Up
app.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const hassedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hassedPassword });
    await user.save();
    res.status(201).json({ message: "User is Created" });
  } catch (err) {
    console.error("Register error:", err);
    // Duplicate key (unique email) error
    if (err.code === 11000) {
      return res.status(409).json({ error: "Email already registered" });
    }
    res.status(500).json({ error: err.message || "Error in registering the user" });
  }
});

// Login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "User not Found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(500).json({ error: "Invalid Login Credentials" });

    // Generating token
    const token = jwt.sign({ userid: user._id }, process.env.JWT_SECRET_KEY, {
      expiresIn: "1h",
    });

    res.json({ token });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: err.message || "login failed" });
  }
});

// Verify the Token
const verifyToken = (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token) return res.status(403).json({ error: "Token not found" });

  jwt.verify(token, process.env.JWT_SECRET_KEY, (err, decoded) => {
    if (err) return res.status(403).json({ error: "Unauthorized User" });
    req.userid = decoded.userid;
    next();
  });
};

// Dashboard
app.get("/dashboard", verifyToken, (req, res) => {
  res.json({ message: `Welcome to Dashboard, User Id: ${req.userid}` });
});

app.listen(process.env.PORT, () => {
  console.log(`Server running on port ${process.env.PORT}`);
});


app.get("/", (req, res) => {
  res.send("Server is running successfully 🚀");
});

app.post("/test", (req, res) => {
  res.json({ message: "POST working" });
});
