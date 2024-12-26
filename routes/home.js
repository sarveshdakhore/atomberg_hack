import express from 'express';
import { hero_home, data } from '../controllers/home.js';

const router = express.Router();

router.get('/', hero_home);
router.get('/data', data);


export default router;