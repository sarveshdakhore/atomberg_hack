import jwt from 'jsonwebtoken';


// Function to generate token link
export const generateTokenLink = (payload,expTime,base_url,route,sec_key) => {
  const token = createToken(payload,expTime,sec_key);
  return `${base_url}/${route}/${token}`;
}


// Function to create a token
export const createToken = (payload,expTime,sec_key) => {
  return jwt.sign(payload, sec_key, { expiresIn: expTime });
};

// Function to verify a token
export const verifyToken = (token,sec_key) => {
  try {
    return jwt.verify(token, sec_key);
  } catch (error) {
    return -1;
  }
};
