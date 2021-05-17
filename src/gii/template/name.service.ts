import { Model, PassportLocalModel } from "mongoose";
import { Injectable } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { debug } from "console";
import { INameService } from "./interfaces/iname.service";
import { IName } from "./interfaces/name.interface";
import { CreateDto, ListDto } from "./dto/name.dto";


@Injectable()
export class NameService implements INameService {
  constructor(
    @InjectModel("Name") private readonly nameModel: PassportLocalModel<IName>
  ) {}
  async findAll(): Promise<IName[]> {
    return await this.nameModel.find().exec();
  }
  
  async list(ListDto: ListDto): Promise<IName[]> {
      let skip = Number(ListDto.skip);
      let limit = Number(ListDto.limit);
    return await this.nameModel.find().skip(skip).limit(limit).exec();
  }

  async findOne(options: object): Promise<IName> {
    return await this.nameModel.findOne(options).exec();
  }

  async findById(ID: number): Promise<IName> {
    return await this.nameModel.findById(ID).exec();
  }
  async create(createDto: CreateDto): Promise<IName> {
    const createdName = new this.nameModel(createDto);
    return await createdName.save();
  }

  async update(ID: number, newValue: IName): Promise<IName> {
    const name = await this.nameModel.findById(ID).exec();

    if (!name._id) {
      debug("user not found");
    }

    await this.nameModel.findByIdAndUpdate(ID, newValue).exec();
    return await this.nameModel.findById(ID).exec();
  }
  async delete(ID: number): Promise<string> {
    try {
      await this.nameModel.findByIdAndRemove(ID).exec();
      return "The user has been deleted";
    } catch (err) {
      debug(err);
      return "The user could not be deleted";
    }
  }
}
