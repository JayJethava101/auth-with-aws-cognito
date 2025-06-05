import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  CognitoIdentityProviderClient,
  AdminAddUserToGroupCommand,
  AdminRemoveUserFromGroupCommand,
  AdminListGroupsForUserCommand,
  ListGroupsCommand,
  CreateGroupCommand,
} from '@aws-sdk/client-cognito-identity-provider';

@Injectable()
export class CognitoRbacService {
  private readonly cognitoClient: CognitoIdentityProviderClient;
  private readonly userPoolId: string;

  constructor(private configService: ConfigService) {
    this.userPoolId = this.configService.get<string>('AWS_COGNITO_USER_POOL_ID') || '';
    
    this.cognitoClient = new CognitoIdentityProviderClient({
      region: this.configService.get<string>('AWS_REGION'),
      credentials: {
        accessKeyId: this.configService.get<string>('AWS_ACCESS_KEY_ID')  || '',
        secretAccessKey: this.configService.get<string>('AWS_SECRET_ACCESS_KEY') || '',
      },
      
    });
  }

  /**
   * Create a new role (group) in Cognito
   */
  async createRole(roleName: string, description: string) {
    const command = new CreateGroupCommand({
      GroupName: roleName,
      Description: description,
      UserPoolId: this.userPoolId,
    });

    return this.cognitoClient.send(command);
  }

  /**
   * List all available roles (groups) in Cognito
   */
  async listRoles(limit: number = 60, nextToken?: string) {
    const command = new ListGroupsCommand({
      UserPoolId: this.userPoolId,
      Limit: limit,
      NextToken: nextToken,
    });

    return this.cognitoClient.send(command);
  }

  /**
   * Assign a role to a user
   */
  async assignRoleToUser(username: string, roleName: string) {
    const command = new AdminAddUserToGroupCommand({
      UserPoolId: this.userPoolId,
      Username: username,
      GroupName: roleName,
    });

    return this.cognitoClient.send(command);
  }

  /**
   * Remove a role from a user
   */
  async removeRoleFromUser(username: string, roleName: string) {
    const command = new AdminRemoveUserFromGroupCommand({
      UserPoolId: this.userPoolId,
      Username: username,
      GroupName: roleName,
    });

    return this.cognitoClient.send(command);
  }

  /**
   * Get all roles for a user
   */
  async getUserRoles(username: string, limit: number = 60, nextToken?: string) {
    const command = new AdminListGroupsForUserCommand({
      UserPoolId: this.userPoolId,
      Username: username,
      Limit: limit,
      NextToken: nextToken,
    });

    return this.cognitoClient.send(command);
  }
}