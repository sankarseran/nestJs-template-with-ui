import { IName } from "./name.interface";

export interface INameService {
  findAll(): Promise<IName[]>;
  findById(ID: number): Promise<IName | null>;
  findOne(options: object): Promise<IName | null>;
  create(name: IName): Promise<IName>;
  update(ID: number, newValue: IName): Promise<IName | null>;
  delete(ID: number): Promise<string>;
}
