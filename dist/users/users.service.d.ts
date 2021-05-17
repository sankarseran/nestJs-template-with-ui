/// <reference types="passport-local-mongoose" />
import { PassportLocalModel } from "mongoose";
import { IUsersService } from "./interfaces/iusers.service";
import { IUser } from "./interfaces/user.interface";
import { CreateUserDto } from "./dto/createUser.dto";
export declare class UsersService implements IUsersService {
    private readonly userModel;
    constructor(userModel: PassportLocalModel<IUser>);
    findAll(): Promise<IUser[]>;
    findOne(options: object): Promise<IUser>;
    findById(ID: number): Promise<IUser>;
    create(createUserDto: CreateUserDto): Promise<IUser>;
    update(ID: number, newValue: IUser): Promise<IUser>;
    delete(ID: number): Promise<string>;
}
