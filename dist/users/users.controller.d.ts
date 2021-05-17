import { CreateUserDto } from "./dto/createUser.dto";
import { UpdateUserDto } from "./dto/updateUser.dto";
import { LoginUserDto } from "./dto/loginUser.dto";
import { ChangePasswordDto } from "./dto/change_password.dto";
import { ForgetPasswordDto, ForgetPasswordResetDto } from "./dto/forgetPassword.dto";
import { UsersService } from "./users.service";
import { Utility } from ".././common/utility";
export declare class UsersController {
    private readonly usersService;
    private readonly Utility;
    constructor(usersService: UsersService, Utility: Utility);
    register(res: any, req: any, CreateUserDto: CreateUserDto): Promise<any>;
    login(res: any, req: any, LoginUserDto: LoginUserDto): Promise<any>;
    logOut(res: any, req: any): Promise<any>;
    view(res: any, req: any): Promise<any>;
    update(res: any, req: any, UpdateUserDto: UpdateUserDto): Promise<any>;
    changePassword(res: any, req: any, ChangePasswordDto: ChangePasswordDto): Promise<any>;
    forgetPassword(res: any, req: any, ForgetPasswordDto: ForgetPasswordDto): Promise<any>;
    resetPassword(res: any, req: any, ForgetPasswordResetDto: ForgetPasswordResetDto): Promise<any>;
}
