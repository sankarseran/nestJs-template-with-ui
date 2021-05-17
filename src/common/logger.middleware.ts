import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response } from 'express';
import  * as jwt from 'jsonwebtoken';
import * as config from "config";
import { Utility } from "./utility";


@Injectable()
export class LoggerMiddleware implements NestMiddleware {
     constructor(private readonly Utility: Utility) {}
  use(req: Request, res: Response, next: Function) {
      try {
     var decoded = jwt.verify(req.headers.authorization, config.jwt.secret);
    req.headers.user_id = decoded['user_id'];
    req.headers.user_role = decoded['role'];
    next();
      } catch (e){
          return this.Utility.sendErr(req,res,e);
      }
  }
}
