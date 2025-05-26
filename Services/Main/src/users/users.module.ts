import { Module, MiddlewareConsumer, RequestMethod } from '@nestjs/common';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';
import { TenantMiddleware } from '../database/tenant.middleware';
import { TenantModule } from '../tenant/tenant.module';
@Module({
  imports: [TenantModule, ],
  controllers: [UsersController],
  providers: [UsersService, ],
})
export class UsersModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(TenantMiddleware)
      .forRoutes({ path: 'users', method: RequestMethod.ALL });
  }
}