import { NestMiddleware } from '@nestjs/common';
import { Request, Response } from 'express';
import { Utility } from "./utility";
export declare class LoggerMiddleware implements NestMiddleware {
    private readonly Utility;
    constructor(Utility: Utility);
    use(req: Request, res: Response, next: Function): any;
}
