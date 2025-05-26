import { Injectable, Inject, Logger, NotFoundException } from '@nestjs/common';
import { DataSource, DataSourceOptions } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ConfigService } from '@nestjs/config';
import { Tenant } from '../tenant/entities/tenant.entity';
import { KmsService } from '../services/kms.service';

@Injectable()
export class DatabaseService {
  private readonly logger = new Logger(DatabaseService.name);
  private tenantConnections = new Map<string, DataSource>();

  constructor(
    @InjectRepository(Tenant, 'management')
    private tenantRepository: Repository<Tenant>,
    private configService: ConfigService,
    @Inject('DATA_SOURCE')
    private defaultDataSource: DataSource,
    private readonly kmsService: KmsService
  ) {}

  async getConnectionForTenant(tenantId: string): Promise<DataSource> {
    // Check if connection exists in cache
    if (this.tenantConnections.has(tenantId)) {
      const connection = this.tenantConnections.get(tenantId);
      
      if (connection && !connection.isInitialized) {
        await connection.initialize();
      }
      
      if (connection) {
        return connection;
      }
    }

    // Get tenant details from management DB
    const tenant = await this.tenantRepository.findOneBy({ id: tenantId });
    if (!tenant) {
      throw new NotFoundException(`Tenant with ID ${tenantId} not found`);
    }

    // todo: Decrypt the stored credentials
    // const dbUser = await this.kmsService.decrypt(tenant.dbUser);
    // const dbPassword = await this.kmsService.decrypt(tenant.dbPassword);
    const dbUser = tenant.dbUser;
    const dbPassword = tenant.dbPassword;

    // Create connection options
    const options: DataSourceOptions = {
      type: 'postgres',
      host: tenant.dbHost,
      port: tenant.dbPort,
      username: dbUser,
      password: dbPassword,
      database: tenant.dbName,
      entities: [__dirname + '/../**/*.entity.{js,ts}'],
      entitySkipConstructor: true,
      synchronize: false,
    };

    // Create and initialize connection
    const connection = new DataSource(options);
    await connection.initialize();
    
    // Cache the connection
    this.tenantConnections.set(tenantId, connection);
    
    return connection;
  }

  async createTenantConnection(tenant: Tenant, dbUser: string, dbPassword: string): Promise<void> {
    // Encrypt credentials before storing
    const encryptedUser = await this.kmsService.encrypt(dbUser);
    const encryptedPassword = await this.kmsService.encrypt(dbPassword);

    // Update tenant with encrypted credentials
    tenant.dbUser = encryptedUser;
    tenant.dbPassword = encryptedPassword;
    await this.tenantRepository.save(tenant);
  }

  async closeAllConnections(): Promise<void> {
    for (const [tenantId, connection] of this.tenantConnections.entries()) {
      if (connection.isInitialized) {
        await connection.destroy();
        this.logger.log(`Closed connection for tenant ${tenantId}`);
      }
    }
    this.tenantConnections.clear();
  }
}