import { Module } from "@nestjs/common";
import { MongooseModule } from "@nestjs/mongoose";
import { CollectionController } from "./collection.controller";
import { CollectionService } from "./collection.service";
import { CollectionSchema } from "./schemas/collection.schema";
import { Utility } from ".././common/utility";

@Module({
  imports: [MongooseModule.forFeature([{ name: "Collection", schema: CollectionSchema }])],
  controllers: [CollectionController],
  
  exports: [
    CollectionService,
    MongooseModule.forFeature([{ name: "Collection", schema: CollectionSchema }])
  ],
  providers: [CollectionService, Utility],
})
export class CollectionModule {}
