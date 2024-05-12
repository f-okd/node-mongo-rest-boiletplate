import nodemailer from 'nodemailer';
import SMTPTransport from 'nodemailer/lib/smtp-transport';
import { IUser } from '../models/userModel';

interface MailtrapTransporter {
  host: string;
}

export default class Email {
  recipientEmail: string;
  recipientName: string;
  senderEmail = `admin <${process.env.EMAIL_FROM}>.com`;

  constructor(user: IUser) {
    this.recipientEmail = user.email;
    this.recipientName = user.name.split(' ')[0];
  }

  newTransport(): nodemailer.Transporter<SMTPTransport.SentMessageInfo> {
    //switch between sendgrid and nodemailer if in dev/prod
    if (process.env.NODE_ENV === 'production') {
      // Sendgrid
      return nodemailer.createTransport({
        service: 'SendGrid',
        auth: {
          user: process.env.SENDGRID_USERNAME,
          pass: process.env.SENDGRID_PASSWORD,
        },
      });
    } else {
      return nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port: process.env.EMAIL_PORT,
        auth: {
          user: process.env.EMAIL_USERNAME,
          pass: process.env.EMAIL_PASSWORD,
        },
      } as SMTPTransport.Options);
    }
  }

  async sendEmail(options: { subject: string; message: string }) {
    // Define email options
    const mailOptions = {
      from: this.senderEmail,
      to: this.recipientEmail,
      subject: options.subject,
      text: options.message,
      // html: <YOU CAN SEND HTML IF YOU WANT. LOOK INTO PUG>
    };

    // Create transport and send email
    if (process.env.NODE_ENV != 'production') {
      await this.newTransport().sendMail(mailOptions);
    }
  }

  sendWelcome() {
    this.sendEmail({
      subject: 'Welcome',
      message: `Welcome to <appName>, ${this.recipientName}`,
    });
  }
}
