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
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const common_1 = require("@nestjs/common");
const class_validator_1 = require("class-validator");
const res_message_1 = require("./res.message");
const mailer_1 = require("@nest-modules/mailer");
const config = require("config");
const winston = require("winston");
winston.configure({
    transports: [
        new (winston.transports.File)({ filename: 'somefile.log' })
    ]
});
let Utility = class Utility {
    constructor(mailerService) {
        this.mailerService = mailerService;
        this.fieldValidate = (data) => __awaiter(this, void 0, void 0, function* () {
            console.log(data);
            console.log(data);
            let errors = yield class_validator_1.validate(data);
            if (errors.length > 0) {
                return { errors: errors, message: res_message_1.ResMessage.VALIDATION_ERROR };
            }
            else {
                return true;
            }
        });
    }
    sendSucc(req, res, data, message) {
        let result = { hasError: false, code: 200, data: data, message: message };
        var log = {};
        log.date = new Date();
        log.api = req.route.path;
        log.method = req.route.methods;
        log.body = req.body;
        log.responce = result;
        winston.log('info', log);
        return res.status(common_1.HttpStatus.OK).json(result);
    }
    sendErr(req, res, e) {
        let result = { hasError: true, code: 400, data: e, message: e.message };
        var log = {};
        log.date = new Date();
        log.api = req.route.path;
        log.method = req.route.methods;
        log.body = req.body;
        log.responce = result;
        winston.error('error', log);
        this
            .mailerService
            .sendMail({
            to: config.mail.error_send_mail,
            from: config.mail.from,
            subject: res_message_1.ResMessage.ERR,
            html: JSON.stringify(log),
        })
            .then(() => { })
            .catch((e) => { console.log(e); });
        return res.status(common_1.HttpStatus.BAD_GATEWAY).json(result);
    }
    sendMail(to, subject, message) {
        this
            .mailerService
            .sendMail({
            to: to,
            from: config.mail.from,
            subject: subject,
            html: message,
        })
            .then(() => { })
            .catch(() => { });
    }
    roleBaseAccess(userRole, role) {
        if (role.indexOf(userRole) < 0) {
            throw { message: res_message_1.ResMessage.ROLE_ERROR };
        }
    }
};
Utility = __decorate([
    common_1.Injectable(),
    __metadata("design:paramtypes", [mailer_1.MailerService])
], Utility);
exports.Utility = Utility;
//# sourceMappingURL=utility.js.map