const express = require('express');
const router = express.Router();

const { profilePageController } = require('../controllers/profile-controller');

router.get('/', profilePageController);

module.exports = router;
