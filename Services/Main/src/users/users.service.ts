import { Injectable, Scope, Inject } from '@nestjs/common';
import { REQUEST } from '@nestjs/core';
import { Request } from 'express';
import { Repository } from 'typeorm';
import { v4 as uuidv4 } from 'uuid';

import { User } from './entities/user.entity';
import { CreateUserDto } from './dto/create-user.dto';
import { RabbitMqService } from '../rabbit-mq/rabbit-mq.service';

@Injectable({ scope: Scope.REQUEST })
export class UsersService {
  private userRepository: Repository<User>;

  constructor(
    @Inject(REQUEST) private request: Request,
    private readonly rabbitMqService: RabbitMqService
  ) {
    // Get the repository from the tenant-specific connection
    this.userRepository = request.tenantConnection.getRepository(User);
  }

  async create(createUserDto: CreateUserDto): Promise<User> {
    const user = new User();
    user.id = uuidv4();
    user.email = createUserDto.email;
    user.name = createUserDto.name;

    const newUser = await this.userRepository.save(user);
    
    // Publish user data to RabbitMQ
    await this.rabbitMqService.publish('user.created', {
      id: newUser.id,
      email: newUser.email,
      name: newUser.name,
      createdAt: newUser.createdAt
    });

    return newUser;
  }

  async findAll(): Promise<User[]> {
    return this.userRepository.find();
  }

  async findOne(id: string): Promise<User | null> {
    return this.userRepository.findOneBy({ id });
  }
}