import { ApiModelProperty } from "@nestjs/swagger";

export class CreateDto {
  fieldReplace
}

export class UpdateDto {
  
  @ApiModelProperty()
  readonly id: string;
  
 fieldReplace
 

}

export class ViewDto {
  
  @ApiModelProperty()
  readonly id: string;
 

}

export class ListDto {
  
  @ApiModelProperty()
  readonly skip: number;
  
  @ApiModelProperty()
  readonly limit: number;
 

}

export class DeleteDto {
  
  @ApiModelProperty()
  readonly id: number;
 

}
