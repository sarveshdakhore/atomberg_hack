import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

dotenv.config(); // Load environment variables


// Configure nodemailer
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL, 
    pass: process.env.EMAIL_PASSWORD, 
  },
  connectionTimeout:10000,
});


// Function to send the email
const sendEmail = (to, subject, htmlContent) => {
  return new Promise((resolve, reject) => {
    const recipients = Array.isArray(to) ? to.join(',') : to;
    const mailOptions = {
      from: process.env.EMAIL,
      to: recipients,
      subject: subject,
      html: htmlContent, 
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Error sending email:', error);
        reject(error);
      } else {
        console.log('Email sent:', info.response);
        resolve(info.response);
      }
    });
  });
}
export default sendEmail;