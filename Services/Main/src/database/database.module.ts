import { Module, Global } from '@nestjs/common';
import { databaseProviders } from './database.providers';
import { DatabaseService } from './database.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Tenant } from 'src/tenant/entities/tenant.entity';
import { KmsService } from 'src/services/kms.service';
@Global()
@Module({
  imports: [
    TypeOrmModule.forFeature([Tenant], 'management'),
    
  ],
  providers: [...databaseProviders, DatabaseService, KmsService],
  exports: [...databaseProviders, DatabaseService],
})
export class DatabaseModule {}