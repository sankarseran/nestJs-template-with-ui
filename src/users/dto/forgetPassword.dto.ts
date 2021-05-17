import { ApiModelProperty } from "@nestjs/swagger";

import {validate, Contains, IsInt, Length, IsEmail, IsFQDN, IsDate, Min, Max} from "class-validator";
 
export class ForgetPasswordValidate {
  
    @IsEmail()
    email: string;
  
}

export class ForgetPasswordDto {
  @ApiModelProperty()
  readonly email: string;
}

export class ForgetPasswordResetDto {
  @ApiModelProperty()
  password: string;
  
  @ApiModelProperty()
  readonly token: string;
}
