import { Entity, Column, PrimaryGeneratedColumn } from 'typeorm';

@Entity('tenants')
export class Tenant {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  name: string;

  @Column({ name: 'db_host' })
  dbHost: string;

  @Column({ name: 'db_port' })
  dbPort: number;

  @Column({ name: 'db_name', unique: true })
  dbName: string;

  @Column({ name: 'db_user', type: 'text' })
  dbUser: string;

  @Column({ name: 'db_password', type: 'text' })
  dbPassword: string;

  @Column({ default: true })
  active: boolean;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  createdAt: Date;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  updatedAt: Date;
}