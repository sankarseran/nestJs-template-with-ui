import { Controller, Get, Render, Res } from "@nestjs/common";
import { AppService } from "./app.service";

import {
  SubscribeMessage,
  WebSocketGateway,
  WebSocketServer,
  WsResponse
} from "@nestjs/websockets";
import { from, Observable } from "rxjs";
import { map } from "rxjs/operators";

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}
  @Get()
  getHello(): string {
    return this.appService.getHello();
  } 
  
  @Get('swagger-spec.json')
test(@Res() res) {
  
  return res.sendFile('swagger-spec.json', {root: __dirname});
}
  
  
}
