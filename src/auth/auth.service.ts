import { Injectable } from '@nestjs/common';
import { CognitoService } from '../cognito/cognito.service';
import { RbacService } from 'src/rbac/rbac.service';
import { GlobalSignOutDto, ChangePasswordDto  } from './dto/auth-dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly cognitoService: CognitoService,
    private readonly rbacService: RbacService,
   
  ) {}

  async signUp(email: string, password: string, name: string) {
    return this.cognitoService.signUp(email, password, name);
  }

  async confirmSignUp(email: string, confirmationCode: string) {
    // // After confirmation succeeds, assign the default role
    // await this.assignDefaultRole(email);
    return this.cognitoService.confirmSignUp(email, confirmationCode);
  }

  async signIn(email: string, password: string) {
    return this.cognitoService.signIn(email, password);
  }

  async initiateMfaSetup(session: string) {
   return this.cognitoService.initiateMfaSetup(session);
  }

  async verifyMFASetup(session: string, totpCode: string) {
    return this.cognitoService.verifyMFASetup(session, totpCode);
  }

  async respondToMFASetupChallenge(session: string, totpCode: string, email: string) {
    return this.cognitoService.respondToMFASetupChallenge(session, totpCode, email);
  }

  async respondToMFAChallenge(session: string, totpCode: string, email: string) {
    return this.cognitoService.respondToMFAChallenge(session, totpCode, email);
  }

  async forgotPassword(email: string) {
    return this.cognitoService.forgotPassword(email);
  }

  async confirmForgotPassword(email: string, password: string, confirmationCode: string) {
    return this.cognitoService.confirmForgotPassword(email, password, confirmationCode);
  }

  async changePassword(changePasswordDto: ChangePasswordDto) {
    const { email, currentPassword, newPassword } = changePasswordDto;
    return this.cognitoService.changePassword(email, currentPassword, newPassword);
  }

  async assignDefaultRole(email: string) {
    // Default role is typically "user"
    await this.rbacService.assignRoleToUser(email, 'user');
  }

  async globalSignOut(globalSignOutDto: GlobalSignOutDto) {
    const { accessToken } = globalSignOutDto;
    
    return this.cognitoService.globalSignOut(accessToken);

  }

  async forcedGlobalSignOut(email: string) {
    return this.cognitoService.forcedGlobalSignOut(email);
  }

  async refreshToken(refreshToken: string) {
    return this.cognitoService.refreshToken(refreshToken);
  }
}