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
import { CreateUserDto } from "./dto/createUser.dto";
import { UpdateUserDto } from "./dto/updateUser.dto";
import { LoginUserDto } from "./dto/loginUser.dto";
import { ChangePasswordDto } from "./dto/change_password.dto";
import { ForgetPasswordDto, ForgetPasswordValidate, ForgetPasswordResetDto } from "./dto/forgetPassword.dto";
import { UsersService } from "./users.service";
import { Utility } from ".././common/utility";
import { ResMessage } from ".././common/res.message";
import {validate, Contains, IsInt, Length, IsEmail, IsFQDN, IsDate, Min, Max} from "class-validator";
import  * as jwt from 'jsonwebtoken';
import * as config from "config";
import { role } from "./schemas/user.schema";

  
  
 
  





@ApiUseTags("users")
@Controller("users")
export class UsersController {
    constructor(
    private readonly usersService: UsersService,
    private readonly Utility: Utility
    
    
      ) {
    
  }
    
  @Post('register')
  public async register(
      @Response() res,
      @Request() req,
      @Body() CreateUserDto: CreateUserDto
      ) {
      try {
          
//Logger.warn('warning')
//Logger.error('something went wrong! ')
      CreateUserDto.created_date_time = new Date();
      const result = await this.usersService.create(CreateUserDto);
      var token = jwt.sign({ user_id: result._id}, config.jwt.secret);
      return this.Utility.sendSucc(req,res,{"token":token},ResMessage.CREATED_SUCC);
      
      } catch (e){
      return this.Utility.sendErr(req,res,e);
      }
  }
  
  
  @Post('login')
  public async login(
      @Response() res,
      @Request() req,
      @Body() LoginUserDto: LoginUserDto
      ) {
      try {
      const result = await this.usersService.findOne(LoginUserDto);
      if (result == null) { throw {message:ResMessage.LOGIN_ERROR} }
      var token = jwt.sign({ user_id: result._id,role: result.role}, config.jwt.secret);
      
      return this.Utility.sendSucc(req,res,{"token":token},ResMessage.LOGIN_SUCC);
      
      
      } catch (e){
      return this.Utility.sendErr(req,res,e);
      }
  }
  
  @Get('logOut')
  public async logOut(
      @Response() res,
      @Request() req
      ) {
      try {
      return this.Utility.sendSucc(req,res,[],ResMessage.LOGOUT_SUCC);
      } catch (e){
      return this.Utility.sendErr(req,res,e);
      }
  }
  
   @Get('view')
   @ApiBearerAuth()
  public async view(
      @Response() res,
      @Request() req,
      ) {
      try {
      this.Utility.roleBaseAccess(req.headers.user_role,[role.USER, role.ADMIN]);    
      const userData = await this.usersService.findOne({_id:req.headers.user_id});
      return this.Utility.sendSucc(req,res,userData,ResMessage.LIST_SUCC);
      } catch (e){
      return this.Utility.sendErr(req,res,e);
      }
  }
  
  @Post('update')
  @ApiBearerAuth()
  public async update(
      @Response() res,
      @Request() req,
      @Body() UpdateUserDto: UpdateUserDto
      ) {
      try {
          
          const userData = await this.usersService.findOne({_id:req.headers.user_id});
          userData.first_name = UpdateUserDto.first_name;
          userData.last_name = UpdateUserDto.last_name;
          userData.email = UpdateUserDto.email;
          var result = await userData.save(); 
      return this.Utility.sendSucc(req,res,result,ResMessage.UPDATE_SUCC);
      } catch (e){
      return this.Utility.sendErr(req,res,e);
      }
  }
  
  @Post('change_password')
  @ApiBearerAuth()
  public async changePassword(
      @Response() res,
      @Request() req,
      @Body() ChangePasswordDto: ChangePasswordDto
      ) {
      try {
          
          const userData = await this.usersService.findOne({_id:req.headers.user_id,password:ChangePasswordDto.old_password});
          if(userData==null) { throw {"message":ResMessage.PASSWORD_NOT_EXISTS} }
          userData.password = ChangePasswordDto.new_password;
          var result = await userData.save();
      return this.Utility.sendSucc(req, res, result,ResMessage.UPDATE_SUCC);
      } catch (e){
      return this.Utility.sendErr(req, res, e);
      }
  }
  
  @Post('forgetPassword')
  public async forgetPassword(
      @Response() res,
      @Request() req,
      @Body() ForgetPasswordDto: ForgetPasswordDto
      ) {
      try {
          let forgetPasswordValidate = new ForgetPasswordValidate();
          forgetPasswordValidate.email = ForgetPasswordDto.email;
          const result = await this.Utility.fieldValidate(forgetPasswordValidate);
          if(result==true) {
              const userData = await this.usersService.findOne({email:ForgetPasswordDto.email});
              userData.forget_password_token=Math.random().toString(36).substr(2);
              var s = new Date();
              s.setMinutes(s.getMinutes()+5);
              userData.forget_password_expried_time=s;
              await userData.save();
              if(userData==null) { throw {message:ResMessage.EMAIL_NOT_EXISTS} }
              this.Utility.sendMail(ForgetPasswordDto.email,ResMessage.FORGET_PASSWORD,ResMessage.FORGET_PASSWORD_MAIL_CONTENT.replace('#TOKEN',userData.forget_password_token));
              return this.Utility.sendSucc(req, res,ForgetPasswordDto,ResMessage.FORGET_PASSWORD_CHECK_MAIL);
          } else {
             throw result;
          }
      } catch (e){
      return this.Utility.sendErr(req, res, e);
      }
  }
  
  @Post('resetPassword')
  public async resetPassword(
      @Response() res,
      @Request() req,
      @Body() ForgetPasswordResetDto: ForgetPasswordResetDto
      ) {
      try {
          const userData = await this.usersService.findOne({forget_password_token:ForgetPasswordResetDto.token,forget_password_expried_time:{"$gte":new Date()}});
          if(userData==null) { throw {'message':ResMessage.RESET_PASSWORD_EXPRIED} }
          userData.password=ForgetPasswordResetDto.password;
          await userData.save();
          return this.Utility.sendSucc(req,res,userData,ResMessage.RESET_PASSWORD_SUCC);
      } catch (e){
      return this.Utility.sendErr(req,res,e);
      }
  }
    
}
