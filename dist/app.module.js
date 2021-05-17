"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", { value: true });
const common_1 = require("@nestjs/common");
const app_controller_1 = require("./app.controller");
const app_service_1 = require("./app.service");
const mongoose_1 = require("@nestjs/mongoose");
const users_module_1 = require("./users/users.module");
const utility_1 = require("./common/utility");
const users_controller_1 = require("./users/users.controller");
const users_service_1 = require("./users/users.service");
const mailer_1 = require("@nest-modules/mailer");
const logger_middleware_1 = require("./common/logger.middleware");
const socket_1 = require("./common/socket");
const config = require("config");
let AppModule = class AppModule {
    configure(consumer) {
        consumer
            .apply(logger_middleware_1.LoggerMiddleware)
            .exclude({ path: 'users/register', method: common_1.RequestMethod.POST }, { path: 'users/resetPassword', method: common_1.RequestMethod.POST }, { path: 'users/login', method: common_1.RequestMethod.POST }, { path: 'users/forgetPassword', method: common_1.RequestMethod.POST })
            .forRoutes(users_controller_1.UsersController);
    }
};
AppModule = __decorate([
    common_1.Module({
        imports: [
            mongoose_1.MongooseModule.forRoot(config.database.link, { useNewUrlParser: true }),
            mailer_1.MailerModule.forRoot({
                transport: config.mail.transport,
                defaults: {
                    from: config.mail.from,
                },
                template: {
                    dir: __dirname + '/templates',
                    adapter: new mailer_1.HandlebarsAdapter(),
                    options: {
                        strict: true,
                    },
                },
            }),
            users_module_1.UsersModule,
            utility_1.Utility
        ],
        controllers: [app_controller_1.AppController, users_controller_1.UsersController],
        providers: [app_service_1.AppService, utility_1.Utility, users_service_1.UsersService, socket_1.EventsGateway]
    })
], AppModule);
exports.AppModule = AppModule;
//# sourceMappingURL=app.module.js.map