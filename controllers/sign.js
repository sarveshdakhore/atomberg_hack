import { generateTokenLink, createToken, verifyToken } from "../utils/token.js";
import sendEmail from "../utils/email.js";
import {hashPassword, verifyPassword} from "../utils/hashing.js"
import prisma from '../DB/dbConfig.js';
import dotenv from 'dotenv';


dotenv.config();
const SECRET_KEY = process.env.SECRET_KEY;
const EXP_TIME_JWT = process.env.EXP_TIME_JWT;
const EXP_TIME_OTP = parseInt(process.env.EXP_TIME_OTP);



// Google sign in
// controllers/googleAuthController.js
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';

const users = [];

// Configure Passport to use Google strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.CALLBACK_URL
    }, (accessToken, refreshToken, profile, done) => {
    // Find or create user in the database
    let user = users.find(u => u.googleId === profile.id);
    if (!user) {
        user = {
        googleId: profile.id,
        displayName: profile.displayName,
        emails: profile.emails
        };
        users.push(user);
    }
    return done(null, user);
}));

// Serialize user to store in session
passport.serializeUser((user, done) => {
    done(null, user.googleId);
});

// Deserialize user from session
passport.deserializeUser((id, done) => {
    const user = users.find(u => u.googleId === id);
    done(null, user);
});

export const googleAuthController = {
    googleAuth: passport.authenticate('google', { scope: ['profile', 'email'] }),
    googleAuthCallback: passport.authenticate('google', { failureRedirect: '/' }),
    googleAuthSuccess: async (req, res) => {
        const user = req.user;
        const userP = await prisma.user.findUnique({
            where: {
                email: user.emails[0].value,
            },
        });
        if (!userP) {
            // user is not present in the database
            // create a new user and generate a jwt token
            await prisma.user.create({
                data:{
                    email: user.emails[0].value,
                    name: user.displayName,
                },
            });
            
        }
        // user is already present in the database
        // generate jwt token
        // increment the token version in the user model
        else{
            await prisma.user.update({
                where: {
                    id: userP.id,
                },
                data: {
                    token_v: userP.token_v + 1,
                },
            });
        }
        
        const cc=await prisma.user.findUnique({
            where: {
                email: user.emails[0].value,
            },
        });
        const payload = {
            email: user.emails[0].value,
            browser: req.headers['user-agent'],
            version: cc.token_v,
        };
        const jwt = createToken(payload, EXP_TIME_JWT, SECRET_KEY);
        // Send user data as JSON response
        // redirection to the FE link where these all will be query parameter and then FE will store it in the local storage
        // FE needs to send a post req to get this jwt from that link
        // hence done with the google sign in
        // add jwt token to GJWT
        // check if exist or not, if not then create else update
        const gjwtData = await prisma.gjwt.findFirst({
            where: {
                userId: cc.id,
            },
        });
        if (gjwtData) {
            await prisma.gjwt.update({
                where: {
                    userId: gjwtData.userId,
                },
                data: {
                    jwt: jwt,
                },
            });
        } else {
            await prisma.gjwt.create({
                data: {
                    jwt: jwt,
                    user: {
                        connect: {
                            id: cc.id,
                        },
                    },
                },
            });
        }
        // redirect to the frontend link with query param
        res.redirect(`http://localhost:3000/sign/gjwt?email=${encodeURIComponent(cc.email)}`);
    }
};

export const getGjwt = async (req, res) => {
    const {email} = req.body;
    const user = await prisma.user.findUnique({
        where: {
            email: email,
        },
    });
    if (!user) {
        return res.status(400).json({ message: "Email not found." });
    }
    const gjwtData = await prisma.gjwt.findFirst({
        where: {
            userId: user.id,
        },
    });
    if (!gjwtData) {
        return res.status(400).json({ message: "JWT not found." });
    }
    // delete the jwt from the database
    await prisma.gjwt.delete({
        where: {
            userId: user.id,
        },
    });
    // check for password
    let password = false;
    const passwordData = await prisma.password.findUnique({
        where: {
            userId: user.id,
        },
    });
    if (passwordData) {
        password = true;
    }
    res.status(200).json({ message: "JWT found.", data: { name:user.name,email:user.email,jwt: gjwtData.jwt, password: password } });

}








// Login
export const hero_login = async (req, res) => {
    // collect the boolean value from body of request var name is otp
    const {email, otp } = req.body;
    const user = await prisma.user.findUnique({
        where: {
            email: email,
        },
    });
    if (!user) {
        return res.status(400).json({ message: "Email not found." });
    }
    // check if the otp is true or false
    // if otp is true then generate a 6 digit random number, create a hash, and save it to OTP model with type = login
    // and send it to the user email
    // if otp is false then check the email and password in the database
    // if the email and password are correct then generate a jwt token and send it to the frontend
    // if the email and password are incorrect then send the error message
    if (otp) {
        // generate 6 digit random number
        const otp = Math.floor(100000 + Math.random() * 900000);
        
        const {hash, salt} = hashPassword(otp.toString());
        // if the user and login type is already there then update the otp, else add it
        const otpData = await prisma.otp.findFirst({
            where: {
                userId: user.id,
                type: "login",
            },
        });
        if (otpData) {
            await prisma.otp.update({
                where: {
                    id: otpData.id,
                },
                data: {
                    otp: hash,
                    salt: salt,
                },
            });
        } else {
            await prisma.otp.create({
                data: {
                    otp: hash,
                    salt: salt,
                    type: "login",
                    expiresAt: new Date(Date.now() + EXP_TIME_OTP), 
                    user: {
                        connect: {
                            id: user.id,
                        },
                    },
                },
            });
        }
        // send the otp to the user email
        await sendEmail(
            email,
            "Login OTP",
            `Your OTP is: ${otp}`
        );
        res.status(200).json({ message: "OTP sent to email." });
    } else {
        // check the email and password in the database
        const passwordData = await prisma.password.findUnique({
            where: {
                userId: user.id,
            },
        });
        if (!passwordData) {
            return res.status(400).json({ message: "Password not found." });
        }
        const { password, salt } = passwordData;
        const { hash } = hashPassword(req.body.password, salt);
        if (hash !== password) {
            return res.status(400).json({ message: "Incorrect password." });
        }
        // generate jwt token
        // increment the token version in the user model
        await prisma.user.update({
            where: {
                id: user.id,
            },
            data: {
                token_v: user.token_v + 1,
            },
        });

        const payload = {
            email: email,
            browser: req.headers["user-agent"],
            version: user.token_v +1,
        };
        const jwt = createToken(payload, EXP_TIME_JWT, SECRET_KEY);
        

        res.status(200).json({ message: "Login successful.", data: { name: user.name,email: email, jwt: jwt, password:true } });
    }
};

// OTP verification
export const login_otp_verify = async (req, res) => {
    const { email, otp } = req.body;
    const user = await prisma.user.findUnique({
        where: {
            email: email,
        },
    });
    if (!user) {
        return res.status(400).json({ message: "Email not found." });
    }
    const otpData = await prisma.otp.findFirst({
        where: {
            userId: user.id,
            type: "login",
        },
    });
    if (!otpData) {
        return res.status(400).json({ message: "OTP not found." });
    }
    const { otp: hash, salt } = otpData;
    const { hash: hashOtp } = hashPassword(otp.toString(), salt);
    if (hashOtp !== hash) {
        return res.status(400).json({ message: "Incorrect OTP." });
    }
    //check expiry time
    if (new Date(otpData.expiresAt) < new Date()) {
        await prisma.otp.delete({
            where: {
                id: otpData.id,
            },
        });
        return res.status(400).json({ message: "OTP expired." });
    }
    // generate jwt token
    // increment the token version in the user model
    await prisma.user.update({
        where: {
            id: user.id,
        },
        data: {
            token_v: user.token_v + 1,
        },
    });
    const payload = {
        email: email,
        browser: req.headers["user-agent"],
        version: user.token_v + 1,
    };
    const jwt = createToken(payload, EXP_TIME_JWT, SECRET_KEY);
    // delete that otp from the database
    await prisma.otp.delete({
        where: {
            id: otpData.id,
        },
    });
    // check password exist or not
    const passwordData = await prisma.password.findUnique({
        where: {
            userId: user.id,
        },
    });
    let password = false;
    if (passwordData) {
        password = true;
    }
    res.status(200).json({ message: "OTP verified.", data: { name:user.name,email: email, jwt: jwt ,password:password} });
};





// Forget password
export const hero_forget = async (req, res)=>{
    try{
        // check does email exist or not
        const { email } = req.body;
        const user = await prisma.user.findUnique({
            where: {
                email: email,
            },
        });
        if (!user) {
            return res.status(400).json({ message: "Email not found." });
        }
        const payload = { email };
        const expTime = "30m";
        const base_url = "http://localhost:3000";
        const route = "sign/reset_pass_page";
        const tokenLink = generateTokenLink(payload, expTime, base_url, route, SECRET_KEY);
        await sendEmail(
            email,
            "Reset your password",
            `Click the link to reset your password: ${tokenLink}`
        );
        res.status(200).json({ message: "Password reset email sent." });
    }
    catch(error){
        // error occured 
        console.error("Error during password reset:", error);
        res.status(500).json({ message: "Password reset failed, please try again later." });
    }
}

export const reset_pass = async (req, res) => {
    let { token } = req.body;
    const {password,passwordC} = req.body;
    if (!token) {
        token = req.params.token;
        if(!token){
            token = req.data.token;
        }
    }
    // check if the passwords match
    if (password !== passwordC) {
        return res.status(400).json({ message: "Passwords do not match." });
    }
    // check password strength
    if (password.length < 8) {
        return res
        .status(400)
        .json({ message: "Password must be at least 8 characters long." });
    }
    const payload = verifyToken(token, SECRET_KEY);
    if (payload === -1) {
        res.status(400).json({ message: "Invalid or expired token." });
    } else {
        const { email } = payload;
        const user = await prisma.user.findUnique({
            where: {
                email: email,
            },
        });
        if (!user) {
            return res.status(400).json({ message: "User not found." });
        }
        // update password
        const { salt, hash } = hashPassword(password);
        try{
            await prisma.password.update({
                where: {
                    userId: user.id,
                },
                data: {
                    password: hash,
                    salt: salt,
                },
            });
            res.status(200).json({ message: "Password reset successful." });
        }
        catch (error) {
            console.error("Error updating password:", error);
            res.status(500).json({ message: "Password reset failed, please try again later." });
        }
    }
}



// update password
export const update_pass = async (req, res) => {
    const { password, passwordC } = req.body;
    const email = req.payload.email;
    // check if the passwords match
    if (password !== passwordC) {
        return res.status(400).json({ message: "Passwords do not match." });
    }
    // check password strength
    if (password.length < 8) {
        return res
        .status(400)
        .json({ message: "Password must be at least 8 characters long." });
    }
    const user = await prisma.user.findUnique({
        where: {
            email: email,
        },
    });
    if (!user) {
        return res.status(400).json({ message: "User not found." });
    }
    // update password
    // check does password exist or not if not then create a new password else update the password
    const passwordData = await prisma.password.findUnique({
        where: {
            userId: user.id,
        },
    });
    if (!passwordData) {
        const { salt, hash } = hashPassword(password);
        try{
            await prisma.password.create({
                data: {
                    password: hash,
                    salt: salt,
                    user: {
                        connect: {
                            id: user.id,
                        },
                    },
                },
            });
            res.status(200).json({ message: "Password updated." });
        }
        catch (error) {
            console.error("Error updating password:", error);
            res.status(500).json({ message: "Password update failed, please try again later." });
        }
    } else {
        const { salt, hash } = hashPassword(password);
        try{
            await prisma.password.update({
                where: {
                    userId: user.id,
                },
                data: {
                    password: hash,
                    salt: salt,
                },
            });
            res.status(200).json({ message: "Password updated." });
        }
        catch (error) {
            console.error("Error updating password:", error);
            res.status(500).json({ message: "Password update failed, please try again later." });
        }
    }
}




// Registration
export const hero_register = async (req, res) => {
    try {
        const { email, password, passwordC } = req.body;
        // check if the email is already in use
        const user = await prisma.user.findUnique({
            where: {
                email: email,
            },
        });
        if (user) {
            return res.status(400).json({ message: "Email already in use." });
        }
        // check if the passwords match
        if (password !== passwordC) {
            return res.status(400).json({ message: "Passwords do not match." });
        }
        // check password strength
        if (password.length < 8) {
            return res
            .status(400)
            .json({ message: "Password must be at least 8 characters long." });
        }
        const payload = { email, password };
        const expTime = "1h";
        const base_url = "http://localhost:3000";
        const route = "sign/verify";
        const tokenLink = generateTokenLink(payload, expTime, base_url, route, SECRET_KEY);
        console.log(tokenLink);
        // await sendEmail(
        // email,
        // "Verify your account",
        // `Click the link to verify your account: ${tokenLink}`
        // );

        res
        .status(200)
        .json({ message: "Registration successful, verification email sent." });
    } catch (error) {
        console.error("Error during registration:", error);
        res
        .status(500)
        .json({ message: "Registration failed, please try again later." });
    }
};


export const reg_verify = async (req, res) => {
    let { token } = req.body;
    if (!token) {
        token = req.params.token;
    }
    console.log(token);
    const payload = verifyToken(token, SECRET_KEY);
    if (payload === -1) {
        res.status(400).json({ message: "Invalid or expired token." });
    } else {
        const { email, password } = payload;
        const { salt, hash } = hashPassword(password);
        try{
            const cc=await prisma.user.create({
                data:{
                    email: email,
                    password:{
                        create:{
                            password: hash,
                            salt: salt,
                        },
                    },
                },
            });
            const payload_new = {
                email: email,
                browser: req.headers["user-agent"],
                version: cc.token_v,
            };
            // check password exists or not
            let passwordT = false;
            const passwordData = await prisma.password.findUnique({
                where: {
                    userId: cc.id,
                },
            });
            if (passwordData) {
                passwordT = true;
            }
            let name = cc.name;
            const jwt=createToken(payload_new,EXP_TIME_JWT, SECRET_KEY);
            res.status(200).json({ message: "Token verified.", data:{name:name,email:email,jwt:jwt,password:passwordT} });
        }
        catch (error) {
            console.error("Error saving user to the database:", error);
            res.status(500).json({ message: "Error saving user to the database." });
        }
    }
}

export const verify_page = (req, res) => {
    const { token } = req.params;
    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Verify Account</title>
        </head>
        <body>
        <h1>Verify Your Account</h1>
        <p>Click the button below to verify your account.</p>
        <form action="/sign/reg_v" method="POST">
            <input type="hidden" name="token" value="${token}">
            <button type="submit">Verify</button>
        </form>
        </body>
        </html>
    `);
};