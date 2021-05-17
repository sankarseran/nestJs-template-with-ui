import { ApiModelProperty } from "@nestjs/swagger";

export class UpdateUserDto {
  
  @ApiModelProperty()
  readonly first_name: string;

  @ApiModelProperty()
  readonly last_name: string;

  @ApiModelProperty()
  readonly email: string;

}
