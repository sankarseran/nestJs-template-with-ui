import { Module } from "@nestjs/common";
import { MongooseModule } from "@nestjs/mongoose";
import { UsersController } from "./users.controller";
import { UsersService } from "./users.service";
import { UserSchema } from "./schemas/user.schema";
import { Utility } from ".././common/utility";

@Module({
  imports: [MongooseModule.forFeature([{ name: "User", schema: UserSchema }])],
  controllers: [UsersController],
  
  exports: [
    UsersService,
    MongooseModule.forFeature([{ name: "User", schema: UserSchema }])
  ],
  providers: [UsersService, Utility],
})
export class UsersModule {}
