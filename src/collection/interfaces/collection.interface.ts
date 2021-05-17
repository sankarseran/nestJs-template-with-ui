import { Document, PassportLocalDocument } from "mongoose";

export interface ICollection extends PassportLocalDocument {
  field: string;
  field1: string;
}
