import { Test, TestingModule } from '@nestjs/testing';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';

describe('UsersController', () => {
  let usersController: UsersController;
  let usersService: UsersService;

  beforeEach(async () => {
    const app: TestingModule = await Test.createTestingModule({
      controllers: [UsersController],
      providers: [UsersService]
    }).compile();

    usersService = app.get<UsersService>(UsersService);
    usersController = app.get<UsersController>(UsersController);
    
  });

  describe('root', () => {
    it('should return ', () => {
      expect(usersController.register('','',{
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
