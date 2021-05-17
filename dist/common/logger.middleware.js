"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", { value: true });
const common_1 = require("@nestjs/common");
const jwt = require("jsonwebtoken");
const config = require("config");
const utility_1 = require("./utility");
let LoggerMiddleware = class LoggerMiddleware {
    constructor(Utility) {
        this.Utility = Utility;
    }
    use(req, res, next) {
        try {
            var decoded = jwt.verify(req.headers.authorization, config.jwt.secret);
            req.headers.user_id = decoded['user_id'];
            req.headers.user_role = decoded['role'];
            next();
        }
        catch (e) {
            return this.Utility.sendErr(res, e);
        }
    }
};
LoggerMiddleware = __decorate([
    common_1.Injectable(),
    __metadata("design:paramtypes", [utility_1.Utility])
], LoggerMiddleware);
exports.LoggerMiddleware = LoggerMiddleware;
//# sourceMappingURL=logger.middleware.js.map