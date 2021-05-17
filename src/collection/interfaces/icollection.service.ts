import { ICollection } from "./collection.interface";

export interface ICollectionService {
  findAll(): Promise<ICollection[]>;
  findById(ID: number): Promise<ICollection | null>;
  findOne(options: object): Promise<ICollection | null>;
  create(collection: ICollection): Promise<ICollection>;
  update(ID: number, newValue: ICollection): Promise<ICollection | null>;
  delete(ID: number): Promise<string>;
}
