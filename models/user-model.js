const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
	name: {
		type: String,
		trim: true,
		minLength: 3,
		maxLength: 20,
		required: [true, 'Name is required'],
	},
	username: {
		type: String,
		required: [true, 'Userame is required'],
		trim: true,
	},
	email: {
		type: String,
		required: [true, 'Email is required'],
		unique: true,
		trim: true,
	},
	password: {
		type: String,
		required: [true, 'Password is required'],
		select: false,
	},
	hisaab: [{ type: mongoose.Schema.Types.ObjectId, ref: 'hisaab' }],
});

module.exports = mongoose.model('User', userSchema);
