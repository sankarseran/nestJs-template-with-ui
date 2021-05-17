import { Test, TestingModule } from '@nestjs/testing';
import { NameController } from './name.controller';
import { NameService } from './name.service';

describe('NameController', () => {
  let nameController: NameController;
  let nameService: NameService;

  beforeEach(async () => {
    const app: TestingModule = await Test.createTestingModule({
      controllers: [NameController],
      providers: [NameService]
    }).compile();

    nameService = app.get<NameService>(NameService);
    nameController = app.get<NameController>(NameController);
    
  });

  describe('root', () => {
    it('should return ', () => {
      expect(nameController.register('','',{
  "first_name": "string",
  "last_name": "string",
  "email": "string12346@gmail.com",
  "password": "string",
  "role": "user",
  "created_date_time": new Date()
})).toBe('Node API Template');
    });
  });
});
