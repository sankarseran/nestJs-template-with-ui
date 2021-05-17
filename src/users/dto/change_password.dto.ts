import { ApiModelProperty } from "@nestjs/swagger";

export class ChangePasswordDto {
  
  @ApiModelProperty()
  readonly old_password: string;

  @ApiModelProperty()
  readonly new_password: string;

  

}
