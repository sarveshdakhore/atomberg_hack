import express from 'express';
import { authMiddleware } from '../middleware/auth.js';
import { hero_login, hero_register, verify_page, reg_verify ,hero_forget, reset_pass, login_otp_verify, update_pass, googleAuthController, getGjwt} from '../controllers/sign.js';

const router = express.Router();


router.post('/login', hero_login);
router.post('/login_otp', login_otp_verify);

// Google sign-in/sign-up route
router.get('/auth/google', googleAuthController.googleAuth);
// Google callback route
router.get('/auth/google/callback', googleAuthController.googleAuthCallback, googleAuthController.googleAuthSuccess);
router.post('/get_gjwt',getGjwt);


router.post('/register', hero_register); // in return of this request, a verification email will be sent to the user
router.get('/verify/:token', verify_page); // this route will be called when the user clicks the verification link in the email
router.post('/reg_v', reg_verify); // when clicked, the verification link will send a POST request to this route AND USER WILL BE REGISTERED

router.post('/forget_password', hero_forget);
router.post('/reset_pass', reset_pass);

router.post('/update_password',authMiddleware, update_pass);
export default router;