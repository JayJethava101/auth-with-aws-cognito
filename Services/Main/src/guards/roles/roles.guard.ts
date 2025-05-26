import { CanActivate, ExecutionContext, Injectable, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable } from 'rxjs';
import { Request } from 'express';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean | Promise<boolean> | Observable<boolean> {
    // Get roles defined on the method
    const handlerRoles = this.reflector.get<string[]>('roles', context.getHandler()) || [];
  
    // Get roles defined on the controller class
    const classRoles = this.reflector.get<string[]>('roles', context.getClass()) || [];
  
    // Combine roles from handler and controller
    const requiredRoles = [...new Set([...classRoles, ...handlerRoles])];
  
    if (requiredRoles.length === 0) {
      return true; // No roles required
    }
  
    const request = context.switchToHttp().getRequest<Request>();
    const user = request['user'];
  
    if (!user) {
      return false;
    }
  
    const userRoles: string[] = user['cognito:groups'] || [];
  
    const hasRequiredRole = requiredRoles.some(role => userRoles.includes(role));
  
    if (!hasRequiredRole) {
      throw new ForbiddenException('Insufficient permissions');
    }
  
    return true;
  }
  
}