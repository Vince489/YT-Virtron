const express = require("express");
const router = express.Router();
const { signupUser, loginUser } = require('./controller');
const User = require("./model");

// Get all users
router.get("/", async (req, res) => {
  try {
      // Fetch all users from the database
      const users = await User.find();
      res.status(200).json(users); // Send the users as a JSON response
  } catch (error) {
      console.error("Error fetching users:", error);
      res.status(500).json({ message: "Internal server error" });
  }
});

// Signup route
router.post('/signup', signupUser);

// Login route
router.post('/login', loginUser);



module.exports = router;
