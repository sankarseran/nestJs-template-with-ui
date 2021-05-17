import { Module } from "@nestjs/common";
import { MongooseModule } from "@nestjs/mongoose";
import { NameController } from "./name.controller";
import { NameService } from "./name.service";
import { NameSchema } from "./schemas/name.schema";
import { Utility } from ".././common/utility";

@Module({
  imports: [MongooseModule.forFeature([{ mongooseN: "Name", schema: NameSchema }])],
  controllers: [NameController],
  
  exports: [
    NameService,
    MongooseModule.forFeature([{ mongooseN: "Name", schema: NameSchema }])
  ],
  providers: [NameService, Utility],
})
export class NameModule {}
