require('dotenv').config();
const bcrypt = require('bcrypt');
const User = require('./model');
const jwt = require('jsonwebtoken');

// User signup
const signupUser = async (req, res) => {
  const { userName, password } = req.body;

  // Validate userName step-by-step
  if (!userName) {
    return res.status(400).json({ message: 'Username is required' });
  }
  if (userName.length < 3) {
    return res.status(400).json({ message: 'Username must be at least 3 characters long' });
  }
  if (userName.length > 20) {
    return res.status(400).json({ message: 'Username must not exceed 20 characters' });
  }
  if (!/^[a-zA-Z0-9_]+$/.test(userName)) {
    return res.status(400).json({
      message: 'Username can only contain letters, numbers, and underscores',
    });
  }

  // Validate password step-by-step
  if (!password) {
    return res.status(400).json({ message: 'Password is required' });
  }
  if (password.length < 8) {
    return res.status(400).json({ message: 'Password must be at least 8 characters long' });
  }
  if (!/[a-z]/.test(password)) {
    return res.status(400).json({ message: 'Password must include at least one lowercase letter' });
  }
  if (!/[A-Z]/.test(password)) {
    return res.status(400).json({ message: 'Password must include at least one uppercase letter' });
  }
  if (!/\d/.test(password)) {
    return res.status(400).json({ message: 'Password must include at least one number' });
  }
  if (!/[@$!%*?&]/.test(password)) {
    return res.status(400).json({ message: 'Password must include at least one special character (@, $, !, %, *, ?, &)' });
  }

  try {
    // Check if the username already exists
    const existingUser = await User.findOne({ userName });
    if (existingUser) {
      return res.status(400).json({ message: 'Username already exists' });
    }

    // Hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Save the new user
    const newUser = new User({ userName, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: 'User created successfully', userName: newUser.userName });
  } catch (error) {
    console.error('Error signing up user:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

// User login
const loginUser = async (req, res) => {
  const { userName, password } = req.body;

  // Validate input
  if (!userName) {
    return res.status(400).json({ message: 'Username is required' });
  }
  if (!password) {
    return res.status(400).json({ message: 'Password is required' });
  }

  try {
    // Find user in the database
    const user = await User.findOne({ userName });
    if (!user) {
      return res.status(400).json({ message: 'Username does not exist' });
    }

    // Compare the password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Incorrect password' });
    }

    // Generate a JWT token
    const token = jwt.sign(
      { id: user._id, userName: user.userName },
      process.env.JWT_SECRET, // Use secret from .env file
      { expiresIn: '1h' } // Token expires in 1 hour
    );

    // IndexedDB instructions
    res.status(200).json({
      message: 'Login successful',
      token, // Return the JWT token
      instructions: 'Store this token securely in IndexedDB for offline support.',
    });
  } catch (error) {
    console.error(`Error during login for username "${userName}": ${error.message}`);
    res.status(500).json({ message: 'Internal server error' });
  }
};

module.exports = { signupUser, loginUser };
