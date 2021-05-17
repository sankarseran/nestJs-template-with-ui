import { ApiModelProperty } from "@nestjs/swagger";
import { role } from ".././schemas/user.schema";

export class CreateUserDto {
  
  @ApiModelProperty()
  readonly first_name: string;

  @ApiModelProperty()
  readonly last_name: string;

  @ApiModelProperty()
  readonly email: string;

  @ApiModelProperty()
  readonly password: string;
  
  @ApiModelProperty({example : role.USER + " || " + role.ADMIN + " || " + role.SUPER_ADMIN})
  readonly role: string;
  
  @ApiModelProperty({example:"2019-05-23T10:02:23.059Z"})
  created_date_time: Date;
}
