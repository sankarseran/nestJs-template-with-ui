import {
  Controller,
  Get,
  Response,
  HttpStatus,
  Param,
  Body,
  Post,
  Request,
  Patch,
  Delete
} from "@nestjs/common";
import { ApiUseTags, ApiResponse, ApiBearerAuth } from "@nestjs/swagger";
import { CreateDto, UpdateDto, ViewDto, ListDto, DeleteDto } from "./dto/collection.dto";
import { CollectionService } from "./collection.service";
import { Utility } from ".././common/utility";
import { ResMessage } from ".././common/res.message";
import {validate, Contains, IsInt, Length, IsEmail, IsFQDN, IsDate, Min, Max} from "class-validator";
import  * as jwt from 'jsonwebtoken';
import * as config from "config";
//import { role } from "./schemas/user.schema";




@ApiUseTags("collection")
@Controller("collection")
export class CollectionController {
    constructor(
    private readonly collectionService: CollectionService,
    private readonly Utility: Utility
    
    
      ) {
    
  }
    
  @Post('create')
  public async create(
      @Response() res,
      @Request() req,
      @Body() CreateDto: CreateDto
      ) {
      try {

      const result = await this.collectionService.create(CreateDto);
      return this.Utility.sendSucc(req,res,result,ResMessage.CREATED_SUCC);
      
      } catch (e){
      return this.Utility.sendErr(req,res,e);
      }
  }
  
  @Post('update')
  public async update(
      @Response() res,
      @Request() req,
      @Body() UpdateDto: UpdateDto
      ) {
      try {

      const collectionData = await this.collectionService.findOne({_id:UpdateDto.id});
      collectionData.field = UpdateDto.field;
      collectionData.field1 = UpdateDto.field1;
      var result = await collectionData.save(); 
          
      return this.Utility.sendSucc(req,res,result,ResMessage.UPDATE_SUCC);
      
      } catch (e){
      return this.Utility.sendErr(req,res,e);
      }
  }
  
  @Get('view/:id')
  public async view(
      @Response() res,
      @Request() req,
      @Param() ViewDto: ViewDto
      ) {
      try {
console.log(ViewDto);
      const collectionData = await this.collectionService.findOne({_id:ViewDto.id});
                
      return this.Utility.sendSucc(req,res,collectionData,ResMessage.LIST_SUCC);
      
      } catch (e){
      return this.Utility.sendErr(req,res,e);
      }
  }
  
  
  @Get('list/:skip/:limit')
  public async list(
      @Response() res,
      @Request() req,
      @Param() ListDto: ListDto
      ) {
      try {

      const collectionData = await this.collectionService.list(ListDto);
                
      return this.Utility.sendSucc(req,res,collectionData,ResMessage.LIST_SUCC);
      
      } catch (e){
      return this.Utility.sendErr(req,res,e);
      }
  }
  
  @Delete('delete')
  public async deleteData(
      @Response() res,
      @Request() req,
      @Body() DeleteDto: DeleteDto
      ) {
      try {

      const collectionData = await this.collectionService.delete(DeleteDto.id);
                
      return this.Utility.sendSucc(req,res,collectionData,ResMessage.LIST_SUCC);
      
      } catch (e){
      return this.Utility.sendErr(req,res,e);
      }
  }
  
  
    
}
