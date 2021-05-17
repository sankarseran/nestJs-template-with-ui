import { Model, PassportLocalModel } from "mongoose";
import { Injectable } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { debug } from "console";
import { ICollectionService } from "./interfaces/icollection.service";
import { ICollection } from "./interfaces/collection.interface";
import { CreateDto, ListDto } from "./dto/collection.dto";


@Injectable()
export class CollectionService implements ICollectionService {
  constructor(
    @InjectModel("Collection") private readonly collectionModel: PassportLocalModel<ICollection>
  ) {}
  async findAll(): Promise<ICollection[]> {
    return await this.collectionModel.find().exec();
  }
  
  async list(ListDto: ListDto): Promise<ICollection[]> {
      let skip = Number(ListDto.skip);
      let limit = Number(ListDto.limit);
    return await this.collectionModel.find().skip(skip).limit(limit).exec();
  }

  async findOne(options: object): Promise<ICollection> {
    return await this.collectionModel.findOne(options).exec();
  }

  async findById(ID: number): Promise<ICollection> {
    return await this.collectionModel.findById(ID).exec();
  }
  async create(createDto: CreateDto): Promise<ICollection> {
    const createdCollection = new this.collectionModel(createDto);
    return await createdCollection.save();
  }

  async update(ID: number, newValue: ICollection): Promise<ICollection> {
    const collection = await this.collectionModel.findById(ID).exec();

    if (!collection._id) {
      debug("user not found");
    }

    await this.collectionModel.findByIdAndUpdate(ID, newValue).exec();
    return await this.collectionModel.findById(ID).exec();
  }
  async delete(ID: number): Promise<string> {
    try {
      await this.collectionModel.findByIdAndRemove(ID).exec();
      return "The user has been deleted";
    } catch (err) {
      debug(err);
      return "The user could not be deleted";
    }
  }
}
