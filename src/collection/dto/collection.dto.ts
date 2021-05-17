import { ApiModelProperty } from "@nestjs/swagger";

export class CreateDto {
  
  @ApiModelProperty()
  readonly field: string;

  @ApiModelProperty()
  readonly field1: string;
 

}

export class UpdateDto {
  
  @ApiModelProperty()
  readonly id: string;
  
  @ApiModelProperty()
  readonly field: string;

  @ApiModelProperty()
  readonly field1: string;
 

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
