const express = require('express');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');

const app = express();
const port = process.env.PORT || 3000;
const SECRET_KEY = 'your_secret_key'; // Use a strong secret key in a real application

app.use(bodyParser.json());

// Mock user data
const users = [
    {
        username: 'testuser',
        password: '$2b$10$CwTycUXWue0Thq9StjUM0uJ8ejho69Xkn0AOwbsXb8G.9R2s4t39a' // hashed password for 'password123'
    }
];

// Mock expenses data
let expenses = [];

// Basic error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('500 - Server Error!');
});

// Middleware for validating JWT token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Authentication endpoint
app.post('/api/auth/login', [
    body('username').isString().trim().escape(),
    body('password').isString().trim().escape()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;

    // Find user
    const user = users.find(u => u.username === username);
    if (!user) {
        return res.status(401).json({ message: 'Invalid username or password' });
    }

    // Check password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
        return res.status(401).json({ message: 'Invalid username or password' });
    }

    // Generate JWT
    const token = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: '1h' });

    res.json({ message: 'Login successful', token });
});

// Get all expenses
app.get('/api/expenses', authenticateToken, (req, res) => {
    res.json(expenses);
});

// Add a new expense
app.post('/api/expenses', authenticateToken, [
    body('description').isString().trim().escape(),
    body('amount').isFloat()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { description, amount } = req.body;

    const newExpense = {
        id: uuidv4(),
        description,
        amount: parseFloat(amount)
    };

    expenses.push(newExpense);
    res.status(201).json(newExpense);
});

// Update an existing expense
app.put('/api/expenses/:id', authenticateToken, [
    body('description').isString().trim().escape(),
    body('amount').isFloat()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { id } = req.params;
    const { description, amount } = req.body;

    // Find expense
    const expense = expenses.find(e => e.id === id);
    if (!expense) {
        return res.status(404).json({ message: 'Expense not found' });
    }

    // Update expense
    expense.description = description;
    expense.amount = parseFloat(amount);

    res.json(expense);
});

// Delete an existing expense
app.delete('/api/expenses/:id', authenticateToken, (req, res) => {
    const { id } = req.params;

    // Find expense index
    const expenseIndex = expenses.findIndex(e => e.id === id);
    if (expenseIndex === -1) {
        return res.status(404).json({ message: 'Expense not found' });
    }

    // Remove expense
    const deletedExpense = expenses.splice(expenseIndex, 1);
    res.json(deletedExpense);
});

// Calculate total expenses
app.get('/api/expense', authenticateToken, (req, res) => {
    const totalExpense = expenses.reduce((total, expense) => total + expense.amount, 0);
    res.json({ totalExpense });
});

app.get('/', (req, res) => {
    res.send('Hello, World!');
});

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port} or http://127.0.0.1:${port}`, '\nPress CTRL + C to stop the server');
});
