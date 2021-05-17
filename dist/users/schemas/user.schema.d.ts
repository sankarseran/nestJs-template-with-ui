import * as mongoose from "mongoose";
export declare enum role {
    USER = "user",
    ADMIN = "admin",
    SUPER_ADMIN = "super_admin"
}
export declare const UserSchema: mongoose.Schema;
