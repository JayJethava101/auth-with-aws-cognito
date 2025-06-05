import { Injectable } from '@nestjs/common';
import { CognitoRbacService } from '../cognito/cognito-rbac.service';

@Injectable()
export class RbacService {
  constructor(private readonly cognitoRbacService: CognitoRbacService) {}

  async createRole(roleName: string, description: string) {
    return this.cognitoRbacService.createRole(roleName, description);
  }

  async listRoles(limit?: number, nextToken?: string) {
    return this.cognitoRbacService.listRoles(limit, nextToken);
  }

  async assignRoleToUser(username: string, roleName: string) {
    return this.cognitoRbacService.assignRoleToUser(username, roleName);
  }

  async removeRoleFromUser(username: string, roleName: string) {
    return this.cognitoRbacService.removeRoleFromUser(username, roleName);
  }

  async getUserRoles(username: string, limit?: number, nextToken?: string) {
    return this.cognitoRbacService.getUserRoles(username, limit, nextToken);
  }
}