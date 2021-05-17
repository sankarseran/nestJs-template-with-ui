import { MailerService } from '@nest-modules/mailer';
export declare class Utility {
    private readonly mailerService;
    constructor(mailerService: MailerService);
    sendSucc(req: any, res: any, data: any, message: any): any;
    fieldValidate: (data: any) => Promise<true | {
        errors: import("class-validator").ValidationError[];
        message: string;
    }>;
    sendErr(req: any, res: any, e: any): any;
    sendMail(to: any, subject: any, message: any): void;
    roleBaseAccess(userRole: any, role: any): void;
}
