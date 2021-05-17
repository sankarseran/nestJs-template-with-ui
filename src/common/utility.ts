//import { HttpStatus, Injectable } from "@nestjs/common";
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
  Delete,
  Injectable
} from "@nestjs/common";
import {validate, Contains, IsInt, Length, IsEmail, IsFQDN, IsDate, Min, Max} from "class-validator";
import { ResMessage } from "./res.message";
import { MailerService } from '@nest-modules/mailer';
import * as config from "config"; 
import * as winston from "winston";

winston.configure({
    transports: [
      new (winston.transports.File)({ filename: 'somefile.log' })
    ]
  })

//  winston.log('info', 'Hello distributed log files!');
//  winston.info('info', 'Hello distributed log files!');
//  winston.warn('info', 'Hello distributed log files!');
//  winston.error('info', 'Hello distributed log files!');

@Injectable()
export class Utility {
         constructor(
  private readonly mailerService: MailerService
    ) {}

  sendSucc(req, res, data, message) {
    let result = { hasError: false, code:200, data: data, message: message };
      
      var log:any = {};
      log.date = new Date();
      log.api = req.route.path;
      log.method = req.route.methods;
      log.body = req.body;
      log.responce = result;
      winston.log('info', log);
    return res.status(HttpStatus.OK).json(result);
  }

   fieldValidate = async (data) => {
       console.log(data);
       console.log(data);
      let errors = await validate(data);
if (errors.length > 0) {
        
        return {errors:errors,message:ResMessage.VALIDATION_ERROR}
    } else {
        return true
    }

  }
  sendErr(req, res, e) {
    let result = { hasError: true,code:400, data: e, message: e.message };
    
          var log:any = {};
      log.date = new Date();
      log.api = req.route.path;
      log.method = req.route.methods;
      log.body = req.body;
      log.responce = result;
      winston.error('error', log);
      
      this
      .mailerService
      .sendMail({
        to: config.mail.error_send_mail, // sender address
        from: config.mail.from, // list of receivers
        subject: ResMessage.ERR, // Subject line
        html: JSON.stringify(log), // HTML body content
      })
      .then(() => {})
      .catch((e) => { console.log(e)});
      
    return res.status(HttpStatus.BAD_GATEWAY).json(result);
  }
  
  sendMail(to,subject,message){
      
      this
      .mailerService
      .sendMail({
        to: to, // sender address
        from: config.mail.from, // list of receivers
        subject: subject, // Subject line
//        text: 'welcome', // plaintext body
        html: message, // HTML body content
      })
      .then(() => {})
      .catch(() => {});
  }
  
    roleBaseAccess(userRole,role){
      if(role.indexOf(userRole)<0) { 
          throw {message : ResMessage.ROLE_ERROR};
      }
  }
  
}
