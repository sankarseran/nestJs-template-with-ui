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
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
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
const swagger_1 = require("@nestjs/swagger");
const createUser_dto_1 = require("./dto/createUser.dto");
const updateUser_dto_1 = require("./dto/updateUser.dto");
const loginUser_dto_1 = require("./dto/loginUser.dto");
const change_password_dto_1 = require("./dto/change_password.dto");
const forgetPassword_dto_1 = require("./dto/forgetPassword.dto");
const users_service_1 = require("./users.service");
const utility_1 = require(".././common/utility");
const res_message_1 = require(".././common/res.message");
const jwt = require("jsonwebtoken");
const config = require("config");
const user_schema_1 = require("./schemas/user.schema");
let UsersController = class UsersController {
    constructor(usersService, Utility) {
        this.usersService = usersService;
        this.Utility = Utility;
    }
    register(res, req, CreateUserDto) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                CreateUserDto.created_date_time = new Date();
                const result = yield this.usersService.create(CreateUserDto);
                var token = jwt.sign({ user_id: result._id }, config.jwt.secret);
                return this.Utility.sendSucc(req, res, { "token": token }, res_message_1.ResMessage.CREATED_SUCC);
            }
            catch (e) {
                return this.Utility.sendErr(req, res, e);
            }
        });
    }
    login(res, req, LoginUserDto) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const result = yield this.usersService.findOne(LoginUserDto);
                if (result == null) {
                    throw { message: res_message_1.ResMessage.LOGIN_ERROR };
                }
                var token = jwt.sign({ user_id: result._id, role: result.role }, config.jwt.secret);
                return this.Utility.sendSucc(req, res, { "token": token }, res_message_1.ResMessage.LOGIN_SUCC);
            }
            catch (e) {
                return this.Utility.sendErr(req, res, e);
            }
        });
    }
    logOut(res, req) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                return this.Utility.sendSucc(req, res, [], res_message_1.ResMessage.LOGOUT_SUCC);
            }
            catch (e) {
                return this.Utility.sendErr(req, res, e);
            }
        });
    }
    view(res, req) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                this.Utility.roleBaseAccess(req.headers.user_role, [user_schema_1.role.USER, user_schema_1.role.ADMIN]);
                const userData = yield this.usersService.findOne({ _id: req.headers.user_id });
                return this.Utility.sendSucc(req, res, userData, res_message_1.ResMessage.LIST_SUCC);
            }
            catch (e) {
                return this.Utility.sendErr(req, res, e);
            }
        });
    }
    update(res, req, UpdateUserDto) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const userData = yield this.usersService.findOne({ _id: req.headers.user_id });
                userData.first_name = UpdateUserDto.first_name;
                userData.last_name = UpdateUserDto.last_name;
                userData.email = UpdateUserDto.email;
                var result = yield userData.save();
                return this.Utility.sendSucc(req, res, result, res_message_1.ResMessage.UPDATE_SUCC);
            }
            catch (e) {
                return this.Utility.sendErr(req, res, e);
            }
        });
    }
    changePassword(res, req, ChangePasswordDto) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const userData = yield this.usersService.findOne({ _id: req.headers.user_id, password: ChangePasswordDto.old_password });
                if (userData == null) {
                    throw { "message": res_message_1.ResMessage.PASSWORD_NOT_EXISTS };
                }
                userData.password = ChangePasswordDto.new_password;
                var result = yield userData.save();
                return this.Utility.sendSucc(req, res, result, res_message_1.ResMessage.UPDATE_SUCC);
            }
            catch (e) {
                return this.Utility.sendErr(req, res, e);
            }
        });
    }
    forgetPassword(res, req, ForgetPasswordDto) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                let forgetPasswordValidate = new forgetPassword_dto_1.ForgetPasswordValidate();
                forgetPasswordValidate.email = ForgetPasswordDto.email;
                const result = yield this.Utility.fieldValidate(forgetPasswordValidate);
                if (result == true) {
                    const userData = yield this.usersService.findOne({ email: ForgetPasswordDto.email });
                    userData.forget_password_token = Math.random().toString(36).substr(2);
                    var s = new Date();
                    s.setMinutes(s.getMinutes() + 5);
                    userData.forget_password_expried_time = s;
                    yield userData.save();
                    if (userData == null) {
                        throw { message: res_message_1.ResMessage.EMAIL_NOT_EXISTS };
                    }
                    this.Utility.sendMail(ForgetPasswordDto.email, res_message_1.ResMessage.FORGET_PASSWORD, res_message_1.ResMessage.FORGET_PASSWORD_MAIL_CONTENT.replace('#TOKEN', userData.forget_password_token));
                    return this.Utility.sendSucc(req, res, ForgetPasswordDto, res_message_1.ResMessage.FORGET_PASSWORD_CHECK_MAIL);
                }
                else {
                    throw result;
                }
            }
            catch (e) {
                return this.Utility.sendErr(req, res, e);
            }
        });
    }
    resetPassword(res, req, ForgetPasswordResetDto) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const userData = yield this.usersService.findOne({ forget_password_token: ForgetPasswordResetDto.token, forget_password_expried_time: { "$gte": new Date() } });
                if (userData == null) {
                    throw { 'message': res_message_1.ResMessage.RESET_PASSWORD_EXPRIED };
                }
                userData.password = ForgetPasswordResetDto.password;
                yield userData.save();
                return this.Utility.sendSucc(req, res, userData, res_message_1.ResMessage.RESET_PASSWORD_SUCC);
            }
            catch (e) {
                return this.Utility.sendErr(req, res, e);
            }
        });
    }
};
__decorate([
    common_1.Post('register'),
    __param(0, common_1.Response()),
    __param(1, common_1.Request()),
    __param(2, common_1.Body()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object, createUser_dto_1.CreateUserDto]),
    __metadata("design:returntype", Promise)
], UsersController.prototype, "register", null);
__decorate([
    common_1.Post('login'),
    __param(0, common_1.Response()),
    __param(1, common_1.Request()),
    __param(2, common_1.Body()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object, loginUser_dto_1.LoginUserDto]),
    __metadata("design:returntype", Promise)
], UsersController.prototype, "login", null);
__decorate([
    common_1.Get('logOut'),
    __param(0, common_1.Response()),
    __param(1, common_1.Request()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object]),
    __metadata("design:returntype", Promise)
], UsersController.prototype, "logOut", null);
__decorate([
    common_1.Get('view'),
    swagger_1.ApiBearerAuth(),
    __param(0, common_1.Response()),
    __param(1, common_1.Request()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object]),
    __metadata("design:returntype", Promise)
], UsersController.prototype, "view", null);
__decorate([
    common_1.Post('update'),
    swagger_1.ApiBearerAuth(),
    __param(0, common_1.Response()),
    __param(1, common_1.Request()),
    __param(2, common_1.Body()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object, updateUser_dto_1.UpdateUserDto]),
    __metadata("design:returntype", Promise)
], UsersController.prototype, "update", null);
__decorate([
    common_1.Post('change_password'),
    swagger_1.ApiBearerAuth(),
    __param(0, common_1.Response()),
    __param(1, common_1.Request()),
    __param(2, common_1.Body()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object, change_password_dto_1.ChangePasswordDto]),
    __metadata("design:returntype", Promise)
], UsersController.prototype, "changePassword", null);
__decorate([
    common_1.Post('forgetPassword'),
    __param(0, common_1.Response()),
    __param(1, common_1.Request()),
    __param(2, common_1.Body()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object, forgetPassword_dto_1.ForgetPasswordDto]),
    __metadata("design:returntype", Promise)
], UsersController.prototype, "forgetPassword", null);
__decorate([
    common_1.Post('resetPassword'),
    __param(0, common_1.Response()),
    __param(1, common_1.Request()),
    __param(2, common_1.Body()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object, forgetPassword_dto_1.ForgetPasswordResetDto]),
    __metadata("design:returntype", Promise)
], UsersController.prototype, "resetPassword", null);
UsersController = __decorate([
    swagger_1.ApiUseTags("users"),
    common_1.Controller("users"),
    __metadata("design:paramtypes", [users_service_1.UsersService,
        utility_1.Utility])
], UsersController);
exports.UsersController = UsersController;
//# sourceMappingURL=users.controller.js.map