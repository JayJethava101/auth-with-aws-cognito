import { Injectable, NestMiddleware, NotFoundException } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { TenantService } from '../tenant/tenant.service';
import { DatabaseService } from './database.service';

// Extend Express Request interface
declare global {
  namespace Express {
    interface Request {
      tenantId: string;
      tenantConnection: any;
    }
  }
}

@Injectable()
export class TenantMiddleware implements NestMiddleware {
  constructor(
    private tenantService: TenantService,
    private databaseService: DatabaseService,
  ) {}

  async use(req: Request, res: Response, next: NextFunction) {
    const tenantId = req.headers['x-tenant-id'] as string;

    if (!tenantId) {
      throw new NotFoundException('Tenant ID is required in the x-tenant-id header');
    }

    try {
      // Verify tenant exists
      const tenant = await this.tenantService.findById(tenantId);
      if (!tenant || !tenant.active) {
        throw new NotFoundException(`Tenant with ID ${tenantId} not found or inactive`);
      }

      // Get database connection for this tenant
      const connection = await this.databaseService.getConnectionForTenant(tenantId);
      
      // Attach tenant info to request
      req.tenantId = tenantId;
      req.tenantConnection = connection;
      
      next();
    } catch (error) {
      next(error);
    }
  }
}

