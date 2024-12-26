import express from 'express';
import sign from './sign.js';
import home from './home.js';
import dataCollection from './dataCollection.js';

const router = express.Router();
router.use('/sign', sign);
router.use('/', home);
router.use("/data",dataCollection);


export default router;