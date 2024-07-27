const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Joi = require('joi');
require('dotenv').config();

const router = express.Router();
const usersFilePath = path.join(__dirname, '../data/users.json');
const jwtSecret = process.env.JWT_SECRET || 'default_secret';

// Helper function to read users from file
const readUsersFromFile = () => {
  const data = fs.readFileSync(usersFilePath, 'utf8');
  return JSON.parse(data);
};

// Helper function to write users to file
const writeUsersToFile = (users) => {
  fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2));
};

// Validate user input
const validateUser = (data) => {
  const schema = Joi.object({
    username: Joi.string().required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required()
  });
  return schema.validate(data);
};

// Register route
router.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    const { error } = validateUser({ username, email, password });
    if (error) return res.status(400).json({ error: error.details[0].message });

    try {
      const users = readUsersFromFile();
      const existingUser = users.find(user => user.email === email);
      if (existingUser) return res.status(400).json({ error: 'Email already in use' });
  
      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = { username, email, password: hashedPassword };
      users.push(newUser);
      writeUsersToFile(users);
      res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
      res.status(500).json({ error: 'Server error' });
    }
});
  
// Login route
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const users = readUsersFromFile();
    const user = users.find(user => user.email === email);
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ email: user.email }, jwtSecret, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
