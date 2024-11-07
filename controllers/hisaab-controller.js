const userModel = require('../models/user-model');
const hisaabModel = require('../models/hisaab-model');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

module.exports.hisaabPageController = async function (req, res) {
	res.render('create');
};

module.exports.createHisaabController = async function (req, res) {
	let { title, description, encrypted, passcode, shareable, editpermissions } =
		req.body;

	encrypted = encrypted === 'on' ? true : false;
	shareable = shareable === 'on' ? true : false;
	editpermissions = editpermissions === 'on' ? true : false;
	try {
		let hisaabCreated = await hisaabModel.create({
			title,
			description,
			user: req.user._id,
			encrypted,
			passcode,
			shareable,
			editpermissions,
		});

		let user = await userModel.findOne({ email: req.user.email });
		user.hisaab.push(hisaabCreated._id);
		await user.save();
		res.redirect('/profile');
	} catch (err) {
		res.send(err.message);
	}
};
module.exports.viewHisaabController = async function (req, res) {
	try {
		const hisaab = await hisaabModel
			.findOne({ _id: req.params.id })
			.populate('user');
		if (!hisaab) return res.redirect('/profile');
		if (hisaab.encrypted)
			return res.render('passcode', {
				loggedin: false,
				id: req.params.id,
			});
		res.render('hisaab', { hisaab, loggedin: false });
	} catch (err) {
		res.send(err.message);
	}
};
module.exports.deleteHisaabController = async function (req, res) {
	const id = req.params.id;
	const hisaab = await hisaabModel.findOne({ _id: id, user: req.user.id });

	if (!hisaab) return res.redirect('/profile');

	await hisaabModel.deleteOne({ _id: id });
	return res.redirect('/profile');
};
module.exports.editHisaabController = async function (req, res) {
	const hisaab = await hisaabModel.findOne({
		_id: req.params.id,
		user: req.user.id,
	});

	res.render('edit', { hisaab, loggedin: false });
};
module.exports.editPostHisaabController = async function (req, res) {
	const hisaab = await hisaabModel.findOne({
		_id: req.params.id,
		user: req.user.id,
	});
	if (!hisaab) return res.redirect('/profile');

	hisaab.title = req.body.title;
	hisaab.description = req.body.description;
	hisaab.editpermissions = req.body.editpermissions === 'on' ? true : false;
	hisaab.shareable = req.body.shareable === 'on' ? true : false;
	hisaab.encrypted = req.body.encrypted === 'on' ? true : false;
	hisaab.passcode = req.body.passcode;

	await hisaab.save();

	res.redirect('/profile');
};
module.exports.verifyHisaabController = async function (req, res) {
	const hisaab = await hisaabModel.findOne({ _id: req.params.id });
	if (hisaab.passcode !== req.body.passcode) return res.redirect('/profile');
	else return res.render('hisaab', { hisaab });
};
