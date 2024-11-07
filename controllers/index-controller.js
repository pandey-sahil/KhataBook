const userModel = require('../models/user-model');
const hisaabModel = require('../models/hisaab-model');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

module.exports.indexPageController = function (req, res) {
	res.render('index', { loggedin: false });
};

module.exports.registerPageController = (req, res) => {
	res.render('register', { loggedin: false });
};

module.exports.registerController = async (req, res) => {
	let { email, username, password, name } = req.body;
	try {
		// Check if the email already exists
		let user = await userModel.findOne({ email });
		if (user) return res.send('You already have an account');

		// Hash the password
		let salt = await bcrypt.genSalt(10);
		let hashed = await bcrypt.hash(password, salt);
		console.log("Hashed password during registration:", hashed); // Log hashed password

		// Create the user
		user = await userModel.create({
			email,
			username,
			name,
			password: hashed,
		});

		// Create JWT token
		let token = jwt.sign(
			{ id: user._id, email: user.email },
			process.env.JWT_KEY
		);
		console.log("JWT Token during registration:", token); // Log JWT token

		// Set the token as a cookie
		res.cookie('token', token);
		res.redirect('/profile');
	} catch (err) {
		console.error("Registration Error:", err.message); // Log error for debugging
		res.send(err.message);
	}
};

module.exports.loginController = async (req, res) => {
	let { email, password } = req.body;

	try {
		// Find the user either by email or username
		let user = await userModel.findOne({
			$or: [{ email }, { username: email }] // Check for email or username match
		}).select('+password'); // Ensure password is also fetched

		if (!user) {
			console.log("User not found"); // Log if user is not found
			return res.send("You don't have an account, please create one");
		}

		// Compare the password
		let result = await bcrypt.compare(password, user.password);
		console.log("Password match result:", result); // Log result of password comparison

		if (result) {
			// Generate a JWT token if password matches
			let token = jwt.sign(
				{ id: user._id, email: user.email },
				process.env.JWT_KEY
			);
			console.log("JWT Token during login:", token); // Log JWT token

			// Set the token in a cookie
			res.cookie('token', token);
			res.redirect('/profile'); // Redirect to the profile page
		} else {
			console.log("Incorrect password"); // Log incorrect password attempt
			return res.send('Incorrect details');
		}
	} catch (err) {
		console.error("Login Error:", err.message); // Log error for debugging
		res.send(err.message);
	}
};

module.exports.logoutController = async (req, res) => {
	// Clear the token from the cookie
	res.cookie('token', '');
	return res.redirect('/'); // Redirect to the homepage
};

module.exports.profileController = async function (req, res) {
	let byDate = Number(req.query.byDate);
	let { startDate, endDate } = req.query;

	try {
		// Default values for date filtering
		byDate = byDate || -1;
		startDate = startDate || new Date('1970-01-01');
		endDate = endDate || new Date();

		// Find the user and their related 'hisaab' entries
		let user = await userModel.findOne({ email: req.user.email }).populate({
			path: 'hisaab',
			match: { createdAt: { $gte: startDate, $lte: endDate } },
			options: { sort: { createdAt: byDate } },
		});

		console.log("User found in profile:", user); // Log user details

		res.render('profile', { user });
	} catch (err) {
		console.error("Profile Error:", err.message); // Log error for debugging
		res.send(err.message);
	}
};
