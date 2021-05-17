"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const mongoose = require("mongoose");
var role;
(function (role) {
    role["USER"] = "user";
    role["ADMIN"] = "admin";
    role["SUPER_ADMIN"] = "super_admin";
})(role = exports.role || (exports.role = {}));
var validateEmail = function (email) {
    var re = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
    return re.test(email);
};
exports.UserSchema = new mongoose.Schema({
    first_name: String,
    last_name: String,
    email: {
        type: String,
        trim: true,
        lowercase: true,
        unique: true,
        required: 'Email address is required',
        validate: [validateEmail, 'Please fill a valid email address'],
        match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please fill a valid email address']
    },
    password: String,
    forget_password_token: String,
    forget_password_expried_time: Date,
    created_date_time: { type: Date },
    role: { type: String, enum: [role.USER, role.ADMIN, role.SUPER_ADMIN] }
});
//# sourceMappingURL=user.schema.js.map