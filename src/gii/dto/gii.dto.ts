import { ApiModelProperty } from "@nestjs/swagger";

export class checkCollectionNameDto {
  
  @ApiModelProperty()
  readonly name: string;
  
  @ApiModelProperty()
  readonly field_name: string[];
  
  @ApiModelProperty()
  readonly field_type: string[];
  
  @ApiModelProperty()
  readonly field_required: string[];

   

}
