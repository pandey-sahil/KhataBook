const express = require('express');
const router = express.Router();

const {
	createHisaabController,
	hisaabPageController,
	viewHisaabController,
	deleteHisaabController,
	editHisaabController,
	editPostHisaabController,
	verifyHisaabController,
} = require('../controllers/hisaab-controller');

const {
	isLoggedIn,
	redirectIfLoggedIn,
} = require('../middlewares/auth-middleware');

router.get('/create', isLoggedIn, hisaabPageController);
router.post('/create', isLoggedIn, createHisaabController);

router.get('/view/:id', isLoggedIn, viewHisaabController);
router.get('/delete/:id', isLoggedIn, deleteHisaabController);

router.get('/edit/:id', isLoggedIn, editHisaabController);
router.post('/edit/:id', isLoggedIn, editPostHisaabController);

router.post('/verify/:id', isLoggedIn, verifyHisaabController);
module.exports = router;
