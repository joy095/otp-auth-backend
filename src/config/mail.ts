/** @format */
import nodemailer, { Transporter } from "nodemailer";

import { SMTPConfig } from "../types";

const smtpConfig: SMTPConfig = {
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT, 10) : undefined,
  secure: false, // true for port 465, false for other ports
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
};

const mailTransporter: Transporter = nodemailer.createTransport(smtpConfig);

export default mailTransporter;
