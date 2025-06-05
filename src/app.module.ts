import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
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
            
    AuthModule,
    
    RbacModule,
    
    UtilsModule,
   
  ],
  providers: [CognitoService],
})
export class AppModule {}
