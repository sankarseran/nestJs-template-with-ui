import { Client, Server, Socket } from "socket.io";
export declare class EventsGateway {
    server: Server;
    client: Client;
    socket: Socket;
    constructor();
    handleConnection(client: any, socket: any): void;
    onMessage(client: any, data: any): Promise<void>;
}
