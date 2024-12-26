import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import prisma from '../DB/dbConfig.js';

dotenv.config();

const SECRET_KEY = process.env.SECRET_KEY;

export const authMiddleware = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  const token = authHeader.split(' ')[1]; // Extract the token from the header
  if (!token) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.payload = decoded;
    
    const user = await prisma.user.findUnique({
      where: {
        email: decoded.email,
      },
    });
    if (!user) {
      return res.status(400).json({ message: 'Invalid token.' });
    }
    console.log(decoded);
    console.log(user);
    const currentTime = Math.floor(Date.now() / 1000); // Convert current time to Unix timestamp
    if (decoded.exp <= currentTime) {
      return res.status(400).json({ message: 'Token has expired.E' });
    }

    if(decoded.browser != req.headers['user-agent']){
      return res.status(400).json({ message: 'Invalid token. B' });
    }
    if(decoded.version != user.token_v){
      return res.status(400).json({ message: 'Invalid token. V' });
    }
    next();
  } catch (error) {
    res.status(400).json({ message: 'Invalid token.' });
  }
};
