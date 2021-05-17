"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const core_1 = require("@nestjs/core");
const app_module_1 = require("./app.module");
const swagger_1 = require("@nestjs/swagger");
const config = require("config");
const fs = require("fs");
function bootstrap() {
    return __awaiter(this, void 0, void 0, function* () {
        let app;
        if (config.env === "local") {
            app = yield core_1.NestFactory.create(app_module_1.AppModule, {
                cors: true
            });
        }
        else {
            const fs = require("fs");
            const privateKey = fs.readFileSync(config.ssl.private);
            const certificate = fs.readFileSync(config.ssl.certificate);
            const bundle = fs.readFileSync(config.ssl.bundle);
            app = yield core_1.NestFactory.create(app_module_1.AppModule, {
                cors: true,
                httpsOptions: {
                    key: privateKey,
                    cert: certificate,
                    ca: bundle
                }
            });
        }
        const options = new swagger_1.DocumentBuilder()
            .setTitle("Node API Template")
            .setDescription("Node API Template")
            .setVersion("1.0")
            .setSchemes("http", "https")
            .addBearerAuth("Authorization", "header", "apiKey")
            .build();
        const document = swagger_1.SwaggerModule.createDocument(app, options);
        fs.writeFileSync("./swagger-spec.json", JSON.stringify(document));
        swagger_1.SwaggerModule.setup("api", app, document);
        yield app.listen(config.projectSetup.port);
    });
}
bootstrap();
//# sourceMappingURL=main.js.map