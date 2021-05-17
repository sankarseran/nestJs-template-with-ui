"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const joi_1 = require("joi");
exports.authUserSchema = joi_1.object({
    email: joi_1.string()
        .email()
        .required(),
    password: joi_1.string()
        .alphanum()
        .min(6)
        .max(36)
        .required()
});
//# sourceMappingURL=auth-user.joi.js.map