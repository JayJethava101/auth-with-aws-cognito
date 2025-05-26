import { Module } from '@nestjs/common';
import { RbacService } from './rbac.service';
import { RbacController } from './rbac.controller';
import { CognitoRbacService } from '../cognito/cognito-rbac.service';

@Module({
  providers: [RbacService, CognitoRbacService],
  controllers: [RbacController],
  exports: [RbacService],
})
export class RbacModule {}