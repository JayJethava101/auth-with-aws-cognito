import { Controller, Post, Body, Get, Param, UseGuards, Query } from '@nestjs/common';
import { RbacService } from './rbac.service';
import { JwtGuard } from '../guards/jwt/jwt.guard';
import { RolesGuard } from '../guards/roles/roles.guard';
import { Roles } from '../decorators/roles.decorator';

@UseGuards(JwtGuard, RolesGuard)
@Roles('admin')
@Controller('rbac')
export class RbacController {
  constructor(private readonly rbacService: RbacService) {}

  @Post('roles')
  async createRole(@Body() payload: { roleName: string; description: string }) {
    const { roleName, description } = payload;
    return this.rbacService.createRole(roleName, description);
  }


  @Get('roles')
  async listRoles(
    @Query('limit') limit?: number,
    @Query('nextToken') nextToken?: string,
  ) {
    return this.rbacService.listRoles(limit, nextToken);
  }

  @Post('users/:username/roles')
  async assignRoleToUser(
    @Param('username') username: string,
    @Body() payload: { roleName: string },
  ) {
    const { roleName } = payload;
    return this.rbacService.assignRoleToUser(username, roleName);
  }

  @Post('users/:username/roles/remove')
  async removeRoleFromUser(
    @Param('username') username: string,
    @Body() payload: { roleName: string },
  ) {
    const { roleName } = payload;
    return this.rbacService.removeRoleFromUser(username, roleName);
  }

  @Get('users/:username/roles')
  async getUserRoles(
    @Param('username') username: string,
    @Query('limit') limit?: number,
    @Query('nextToken') nextToken?: string,
  ) {
    return this.rbacService.getUserRoles(username, limit, nextToken);
  }
}