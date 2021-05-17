import { Module } from "@nestjs/common";
import { MongooseModule } from "@nestjs/mongoose";
import { GiiController } from "./gii.controller";
import { Utility } from ".././common/utility";

@Module({
  imports: [],
  controllers: [GiiController],
  
  exports: [],
  providers: [Utility]
})
export class GiiModule {}
