import { Document, PassportLocalDocument } from "mongoose";

export interface IUser extends PassportLocalDocument {
  first_name: string;
  last_name: string;
  email: string;
  password: string;
  forget_password_token: string;
  forget_password_expried_time: date;
  role: string;
  created_date_time: date;
}
