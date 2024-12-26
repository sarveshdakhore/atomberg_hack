import express from 'express';
import { collectAndSaveData } from '../controllers/dataCollection.js';
import { authMiddleware } from '../middleware/auth.js';

const router = express.Router();

router.post('/send',authMiddleware, collectAndSaveData);


export default router;