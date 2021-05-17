import {
  SubscribeMessage,
  WebSocketGateway,
  WebSocketServer,
  WsResponse
} from "@nestjs/websockets";
import { Injectable, UseFilters, UseGuards } from "@nestjs/common";
import { from, Observable } from "rxjs";
import { map } from "rxjs/operators";
import { Client, Server, Socket } from "socket.io";



@WebSocketGateway()
export class EventsGateway {
  @WebSocketServer()
  server: Server;
  public client: Client;
  socket: Socket;
  //  utility:Utility;

  constructor() {}

  handleConnection(client, socket) {
    client.on("message", async data => {});
  }

  @SubscribeMessage("message")
  async onMessage(client, data: any) {
   
  }
}
