import { Injectable } from '@nestjs/common';
import { CognitoService } from '../cognito/cognito.service';
import { SignUpDto } from './dto/signup.dto';
import { ConfirmSignUpDto } from './dto/confirm-signup.dto';
import { SignInDto } from './dto/signin.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { RbacService } from 'src/rbac/rbac.service';
import { GlobalSignOutDto } from './dto/global-signout.dto';
import { ForcedGlobalSignOutDto } from './dto/forced-global-signout.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly cognitoService: CognitoService,
    private readonly rbacService: RbacService,
   
  ) {}

  async signUp(signUpDto: SignUpDto) {
    const { email, password, name } = signUpDto;
    
    const userAttributes = [
      {
        Name: 'name',
        Value: name,
      },
      {
        Name: 'email',
        Value: email,
      },
    ];

    // Optionally assign a default role
    // Note: You need to wait for the user to be confirmed before assigning roles
    
   

    return this.cognitoService.signUp(email, password, userAttributes);
  }

  async confirmSignUp(confirmSignUpDto: ConfirmSignUpDto) {
    const { email, confirmationCode } = confirmSignUpDto;

    // After confirmation succeeds, assign the default role
    await this.assignDefaultRole(email);
    
    return this.cognitoService.confirmSignUp(email, confirmationCode);
  }

  async signIn(signInDto: SignInDto) {
    const { email, password } = signInDto;
    return this.cognitoService.signIn(email, password);
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

  async forcedGlobalSignOut(adminGlobalSignOutDto: ForcedGlobalSignOutDto   ) {
    const { username } = adminGlobalSignOutDto;
    return this.cognitoService.forcedGlobalSignOut(username);
  }

  async refreshToken(refreshToken: string) {
    return this.cognitoService.refreshToken(refreshToken);
  }
  
}