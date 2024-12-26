import crypto from 'crypto';

// Function to hash a password with a salt
const hashPassword = (password, salt = crypto.randomBytes(16).toString('hex')) => {
  const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
  return { salt, hash };
};

// Function to verify a password with a given salt and hash
const verifyPassword = (password, salt, hash) => {
  const hashToVerify = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
  return hash === hashToVerify;
};

export { hashPassword, verifyPassword };