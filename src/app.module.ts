import { Module, NestModule, MiddlewareConsumer, RequestMethod } from "@nestjs/common";
import { AppController } from "./app.controller";
import { AppService } from "./app.service";
import { MongooseModule } from "@nestjs/mongoose";
import { UsersModule } from "./users/users.module";
import { GiiModule } from "./gii/gii.module";
import { Utility } from "./common/utility";
//import { UsersService } from "./users/users.service";
//import { UsersController } from "./users/users.controller";
import { UsersController } from "./users/users.controller";
import { GiiController } from "./gii/gii.controller";
import { UsersService } from "./users/users.service";
import { HandlebarsAdapter, MailerModule } from '@nest-modules/mailer';
import { LoggerMiddleware } from './common/logger.middleware';
import { EventsGateway } from "./common/socket";

import { CollectionModule } from "./collection/collection.module";
import { CollectionController } from "./collection/collection.controller";
import { CollectionService } from "./collection/collection.service";

import { SampleModule } from "./sample/sample.module";
import { SampleController } from "./sample/sample.controller";
import { SampleService } from "./sample/sample.service";

import * as config from "config";

@Module({
  imports: [ 
    MongooseModule.forRoot(config.database.link, { useNewUrlParser: true }),
    MailerModule.forRoot({
      transport: config.mail.transport,
      defaults: {
        from: config.mail.from,
      },
      template: {
        dir: __dirname + '/templates',
        adapter: new HandlebarsAdapter(), // or new PugAdapter()
        options: {
          strict: true,
        },
      },
    }),
    UsersModule,
    GiiModule,
    CollectionModule,
    SampleModule,
    Utility
  ],
//  controllers: [AppController,UsersController, GiiController],
//  providers: [AppService, Utility, UsersService, EventsGateway]
  controllers: [AppController,UsersController, GiiController,CollectionController, SampleController],
  providers: [AppService, Utility, UsersService, EventsGateway, CollectionService, SampleService]
})
//export class AppModule {}

export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(LoggerMiddleware)
      .exclude(
    { path: 'users/register', method: RequestMethod.POST },
    { path: 'users/resetPassword', method: RequestMethod.POST },
    { path: 'users/login', method: RequestMethod.POST },
    { path: 'users/forgetPassword', method: RequestMethod.POST }
  )
      .forRoutes(UsersController);
  }
}
