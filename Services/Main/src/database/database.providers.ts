import { DataSource, DataSourceOptions } from 'typeorm';
import { Provider } from '@nestjs/common';

export const databaseProviders: Provider[] = [
  {
    provide: 'DATA_SOURCE',
    useFactory: async () => {
      const dataSource = new DataSource({
        type: 'postgres',
        host: process.env.PG_HOST || 'localhost',
        port: 5432,
        username: process.env.PG_USER || 'postgres',
        password: process.env.PG_PASSWORD || 'postgres',
        database: 'postgres', // Default postgres database
      });

      return dataSource.initialize();
    },
  },
];
