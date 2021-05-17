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
import { CreateDto, UpdateDto, ViewDto, ListDto, DeleteDto } from "./dto/name.dto";
import { NameService } from "./name.service";
import { Utility } from ".././common/utility";
import { ResMessage } from ".././common/res.message";
import {validate, Contains, IsInt, Length, IsEmail, IsFQDN, IsDate, Min, Max} from "class-validator";
import  * as jwt from 'jsonwebtoken';
import * as config from "config";
//import { role } from "./schemas/user.schema";




@ApiUseTags("name")
@Controller("name")
export class NameController {
    constructor(
    private readonly nameService: NameService,
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

      const result = await this.nameService.create(CreateDto);
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

      const nameData = await this.nameService.findOne({_id:UpdateDto.id});
      fieldReplace
      var result = await nameData.save(); 
          
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
      const nameData = await this.nameService.findOne({_id:ViewDto.id});
                
      return this.Utility.sendSucc(req,res,nameData,ResMessage.LIST_SUCC);
      
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

      const nameData = await this.nameService.list(ListDto);
                
      return this.Utility.sendSucc(req,res,nameData,ResMessage.LIST_SUCC);
      
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

      const nameData = await this.nameService.delete(DeleteDto.id);
                
      return this.Utility.sendSucc(req,res,nameData,ResMessage.LIST_SUCC);
      
      } catch (e){
      return this.Utility.sendErr(req,res,e);
      }
  }
  
  
    
}
