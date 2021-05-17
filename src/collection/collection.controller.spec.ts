import { Test, TestingModule } from '@nestjs/testing';
import { CollectionController } from './collection.controller';
import { CollectionService } from './collection.service';

describe('CollectionController', () => {
  let collectionController: CollectionController;
  let collectionService: CollectionService;

  beforeEach(async () => {
    const app: TestingModule = await Test.createTestingModule({
      controllers: [CollectionController],
      providers: [CollectionService]
    }).compile();

    collectionService = app.get<CollectionService>(CollectionService);
    collectionController = app.get<CollectionController>(CollectionController);
    
  });

  describe('root', () => {
    it('should return ', () => {
      expect(collectionController.register('','',{
  "first_collection": "string",
  "last_collection": "string",
  "email": "string12346@gmail.com",
  "password": "string",
  "role": "user",
  "created_date_time": new Date()
})).toBe('Node API Template');
    });
  });
});
