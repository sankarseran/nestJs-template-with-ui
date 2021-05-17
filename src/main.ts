import { NestFactory } from "@nestjs/core";
import { AppModule } from "./app.module";
import { SwaggerModule, DocumentBuilder } from "@nestjs/swagger";
import * as config from "config";
import * as fs from 'fs';
import * as path from "path";
import { join } from 'path';

async function bootstrap() {
  let app;
  if (config.env === "local") {
    app = await NestFactory.create(AppModule, {
      cors: true
    });
   
   
  } else {
    const fs = require("fs");
    const privateKey = fs.readFileSync(config.ssl.private);
    const certificate = fs.readFileSync(config.ssl.certificate);
    const bundle = fs.readFileSync(config.ssl.bundle);

    app = await NestFactory.create(AppModule, {
      cors: true,
      httpsOptions: {
        key: privateKey,
        cert: certificate,
        ca: bundle
      }
    });
  } 
 
  app.useStaticAssets(join(__dirname, '..', 'src/public'));
//  app.useStaticAssets({
//    root: join(__dirname, '..', 'src/public'),
//    prefix: '/public/',
//  });
  
  app.setBaseViewsDir(join(__dirname, '..', 'src/views'));
  app.setViewEngine('hbs');

  const options = new DocumentBuilder()
    .setTitle("Node API Template")
    .setDescription("Node API Template")
    .setVersion("1.0")
    .setSchemes("http", "https")
    //    .addTag("communication")
    .addBearerAuth("Authorization", "header", "apiKey")
    .build();
  //    .addBearerAuth('Authorization', 'header','apiKey');
    
  const document = SwaggerModule.createDocument(app, options);
fs.writeFileSync("./swagger-spec.json", JSON.stringify(document));
  SwaggerModule.setup("api", app, document);

  await app.listen(config.projectSetup.port);
}
bootstrap();
