import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { TenantModule } from './tenant/tenant.module';
import { DatabaseModule } from './database/database.module';
import { UsersModule } from './users/users.module';
import { RabbitMqModule } from './rabbit-mq/rabbit-mq.module';
import { CognitoService } from './cognito/cognito.service';
import { AuthModule } from './auth/auth.module';
import { RbacModule } from './rbac/rbac.module';
import { RedisModule } from '@nestjs-modules/ioredis';
import { UtilsModule } from './utils/utils.module';



@Module({
  imports: [
    // Global configuration
    ConfigModule.forRoot({
      isGlobal: true,
    }),

    RedisModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        type: 'single',
        url: configService.get('REDIS_URL', 'redis://localhost:6379'),
      }),
    }),
    
    // Central management database connection
    TypeOrmModule.forRoot({
      name: 'management',
      type: 'postgres',
      host: process.env.PG_HOST || 'localhost',
      port: 5432,
      username: process.env.PG_USER || 'postgres',
      password: process.env.PG_PASSWORD || 'postgres',
      database: process.env.PG_MANAGEMENT_DB || 'saas_management',
      entities: [__dirname + '/tenant/entities/*.entity.{js,ts}'],
      synchronize: true, // Set to false in production
    }),
    
    TenantModule,
    
    DatabaseModule,
    
    UsersModule,
    
    RabbitMqModule,
    
    AuthModule,
    
    RbacModule,
    
    UtilsModule,
    
   
  ],
  providers: [CognitoService],
})
export class AppModule {}
