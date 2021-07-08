const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  host: process.env.MAIL_host,
  port: process.env.MAIL_port,
  secure: false, 
  auth: {
    user: process.env.MAIL_user,
    pass: process.env.MAIL_password
  }
});

const sendEmail = (to, subject, content) =>{
    console.log({
        user: process.env.MAIL_user,
        pass: process.env.MAIL_password
      })
    var mailOptions = {
        from: process.env.MAIL_email,
        to: to,
        subject: subject,
        html: content
      };
      
      transporter.sendMail(mailOptions, function(error, info){
        if (error) {
          console.log(error);
        } else {
          console.log('Email sent: ' + info.response);
        }
      });
};

module.exports = {
    sendEmail,
};