import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { TenantController } from './tenant.controller';
import { TenantService } from './tenant.service';
import { Tenant } from './entities/tenant.entity';
import { DatabaseModule } from '../database/database.module';
import { DataSource, DataSourceOptions } from 'typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { KmsService } from 'src/services/kms.service';
const databaseConfig = (configService: ConfigService): DataSourceOptions => ({
  type: 'postgres',
  name: 'management',
  host: configService.get<string>('PG_HOST', 'localhost'),
  port: configService.get<number>('PG_PORT', 5432),
  username: configService.get<string>('PG_USER', 'postgres'),
  password: configService.get<string>('PG_PASSWORD', 'postgres'),
  database: configService.get<string>('PG_MANAGEMENT_DB', 'saas_management'),
  entities: [Tenant],
  synchronize: true,
});

@Module({
  imports: [
    ConfigModule,
    TypeOrmModule.forRootAsync({
      name: 'management',
      imports: [ConfigModule], // Que: Why is this needed?
      useFactory: databaseConfig,
      inject: [ConfigService], // Que: Why is this needed?
      // This tells NestJS to inject the ConfigService into your factory function. 
      // Your databaseConfig function probably receives ConfigService as a parameter 
      // to read configuration values.
    }),
    TypeOrmModule.forFeature([Tenant], 'management'), // The second parameter 'management' specifying that this entity belongs to that specific database connection.
    DatabaseModule,
  ],
  controllers: [TenantController],
  providers: [
    TenantService,
    // {
    //   provide: 'MANAGEMENT_DATA_SOURCE',
    //   useFactory: async (configService: ConfigService) => {
    //     const dataSource = new DataSource(databaseConfig(configService));
    //     await dataSource.initialize();
    //     return dataSource;
    //   },
    //   inject: [ConfigService],
    // },
    KmsService,
  ],
  exports: [TenantService],
})
export class TenantModule {}