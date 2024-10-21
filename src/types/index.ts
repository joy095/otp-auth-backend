/** @format */

export interface SMTPConfig {
  host: string | undefined;
  port: number | undefined;
  secure: boolean;
  auth: {
    user: string | undefined;
    pass: string | undefined;
  };
}
