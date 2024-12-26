import express from 'express';
import env from 'dotenv';
import bodyParser from 'body-parser';
import router from './routes/routes.js';
import cors from 'cors';
import cron from 'node-cron';
import deleteExpiredOtps from './utils/deleteExpiredOTPs_shedule.js';
import session from 'express-session';
import passport from 'passport';

env.config();

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());
app.use(bodyParser.json());
app.use(cors({
    origin: "*",
    methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
    preflightContinue: false,
}));
app.use(express.urlencoded({ extended: true }));

// Configure session
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-default-secret',
    resave: false,
    saveUninitialized: true,
}));

// Initialize Passport and restore authentication state, if any, from the session
app.use(passport.initialize());
app.use(passport.session());

app.use(router);

// Schedule the deleteExpiredOtps function to run every day
cron.schedule('0 0 * * *', () => {
    deleteExpiredOtps();
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});