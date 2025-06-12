import { Injectable, BadRequestException, UnauthorizedException } from '@nestjs/common';
import * as crypto from 'crypto';
import { ConfigService } from '@nestjs/config';
import {
  CognitoIdentityProviderClient,
  InitiateAuthCommand,
  SignUpCommand,
  ConfirmSignUpCommand,
  ForgotPasswordCommand,
  ConfirmForgotPasswordCommand,
  ChangePasswordCommand,
  AdminUserGlobalSignOutCommand,
  GlobalSignOutCommand,
  AssociateSoftwareTokenCommand,
  VerifySoftwareTokenCommand,
  SetUserMFAPreferenceCommand,
  RespondToAuthChallengeCommand,
  AuthFlowType,
  ChallengeNameType,
  AdminGetUserCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import {
  UserNotFoundException,
  UserNotConfirmedException,
  InvalidPasswordException,
  NotAuthorizedException,
  UsernameExistsException,
  CodeMismatchException,
  ExpiredCodeException,
  LimitExceededException,
  TooManyRequestsException,
  InvalidParameterException
} from '../auth/exceptions/cognito-exceptions';
import { TokenRevocationService } from 'src/utils/token.revocation.service';

@Injectable()
export class CognitoService {
  private readonly cognitoClient: CognitoIdentityProviderClient;
  private readonly userPoolId: string;
  private readonly clientId: string;
  private readonly clientSecret: string;

  constructor(private configService: ConfigService, private tokenRevocationService: TokenRevocationService) {
    this.userPoolId = this.configService.get<string>('AWS_COGNITO_USER_POOL_ID') || '';
    this.clientId = this.configService.get<string>('AWS_COGNITO_CLIENT_ID') || '';
    this.clientSecret = this.configService.get<string>('AWS_COGNITO_CLIENT_SECRET') || '';
    
    this.cognitoClient = new CognitoIdentityProviderClient({
      region: this.configService.get<string>('AWS_REGION'),
      credentials: {
        accessKeyId: this.configService.get<string>('AWS_ACCESS_KEY_ID') || '',
        secretAccessKey: this.configService.get<string>('AWS_SECRET_ACCESS_KEY') || '',
      },
    });
  }

  /**
   * Handle Cognito errors and map them to custom exceptions
   */
  private handleCognitoError(error: any): never {
    if (error.name === 'UsernameExistsException') {
      throw new UsernameExistsException();
    } else if (error.name === 'InvalidPasswordException') {
      throw new InvalidPasswordException();
    } else if (error.name === 'InvalidParameterException') {
      throw new InvalidParameterException(error.message);
    } else if (error.name === 'TooManyRequestsException') {
      throw new TooManyRequestsException();
    }

    console.log('Re-throw the original error', error)
    // If not a known error, re-throw the original
    throw error;
  }

  private generateSecretHash(username: string): string {
    return crypto
      .createHmac('SHA256', this.clientSecret)
      .update(username + this.clientId)
      .digest('base64');
  }

  async signUp(email: string, password: string, name: string) {
    const params = {
      ClientId: this.clientId,
      Username: email,
      Password: password,
      SecretHash: this.generateSecretHash(email),
      UserAttributes: [
        {
          Name: 'email',
          Value: email,
        },
        {
          Name: 'name',
          Value: name,
        },
        {
          Name: 'custom:tenantId',
          Value: '12345', // the tenantId need to get from the invitaton link
        }
      ],
    };

    try {
      const command = new SignUpCommand(params);
      const result = await this.cognitoClient.send(command);
      console.log('SignUp',result)
      return {
        userSub: result.UserSub,
        message: 'User registration successful. Please check your email for verification code.',
      };
    } catch (error) {
      this.handleCognitoError(error);
    }
  }

  async confirmSignUp(email: string, confirmationCode: string) {
    const params = {
      ClientId: this.clientId,
      Username: email,
      ConfirmationCode: confirmationCode,
      SecretHash: this.generateSecretHash(email),
    };

    try {
      const command = new ConfirmSignUpCommand(params);
      await this.cognitoClient.send(command);

      // After successful confirmation, get the user's attributes including sub
      const adminGetUserCommand = new AdminGetUserCommand({
        UserPoolId: this.userPoolId,
        Username: email,
      });

      const userResult = await this.cognitoClient.send(adminGetUserCommand);
      const userId = userResult.UserAttributes?.find(attr => attr.Name === 'sub')?.Value;
      const tenantId = userResult.UserAttributes?.find(attr => attr.Name === 'custom:tenantId')?.Value;
      console.log(userResult)
      
      // todo: creat user-tenant mapping in the cental database
      

      return { 
        message: 'Email verification successful',
        userResult
      };
    } catch (error) {
      this.handleCognitoError(error);
    }
  }

  async signIn(email: string, password: string) {
    const params = {
      ClientId: this.clientId,
      AuthFlow: AuthFlowType.USER_PASSWORD_AUTH,
      AuthParameters: {
        USERNAME: email,
        PASSWORD: password,
        SECRET_HASH: this.generateSecretHash(email),
      },
    };

    try {
      const command = new InitiateAuthCommand(params);
      const result = await this.cognitoClient.send(command);

    

      if (result.ChallengeName === ChallengeNameType.SOFTWARE_TOKEN_MFA) {
        return {
          challengeName: result.ChallengeName,
          session: result.Session,
          message: 'MFA challenge required. Please provide TOTP code.',
        };
      }

      if (result.ChallengeName === ChallengeNameType.MFA_SETUP) {
        return {
          challengeName: result.ChallengeName,
          session: result.Session,
          message: 'MFA setup required. Please set up TOTP first.',
        };
      }

      return {
        accessToken: result.AuthenticationResult?.AccessToken,
        refreshToken: result.AuthenticationResult?.RefreshToken,
        idToken: result.AuthenticationResult?.IdToken,
      };
    } catch (error) {
      this.handleCognitoError(error);
    }
  }

  async initiateMfaSetup(session: string) {
    const params = {
      Session: session,
    };

    try {
      const command = new AssociateSoftwareTokenCommand(params);
      const result = await this.cognitoClient.send(command);

      // Generate QR code url for the secret
      const secretCode = result.SecretCode;
      const qrCodeUrl = `otpauth://totp/YourApp:user?secret=${secretCode}&issuer=YourApp`;
  

      return {
        secretCode,
        qrCodeUrl,
        session: result.Session,
        message: 'Scan this QR code with your authenticator app',
      };
    } catch (error) {
      this.handleCognitoError(error);
    }
  }

  async verifyMFASetup(session: string, totpCode: string) {
    const params = {
      Session: session,
      UserCode: totpCode,
    };

    try {
      const command = new VerifySoftwareTokenCommand(params);
      const result = await this.cognitoClient.send(command);

      if (result.Status === 'SUCCESS') {
        return {
          status: result.Status,
          session: result.Session,
          message: 'MFA setup completed successfully',
        };
      }

      throw new BadRequestException('Invalid TOTP code');
    } catch (error) {
      this.handleCognitoError(error);
    }
  }

  async respondToMFASetupChallenge(session: string, totpCode: string, email: string) {
    const params = {
      ClientId: this.clientId,
      ChallengeName: ChallengeNameType.MFA_SETUP,
      Session: session,
      ChallengeResponses: {
        USERNAME: email,
        SOFTWARE_TOKEN_MFA_CODE: totpCode,
        SECRET_HASH: this.generateSecretHash(email),
      },
    };

    try {
      const command = new RespondToAuthChallengeCommand(params);
      const result = await this.cognitoClient.send(command);

      // After successful MFA setup challenge, we can set MFA preferences
      if (result.AuthenticationResult?.AccessToken) {
        try {
          const mfaParams = {
            AccessToken: result.AuthenticationResult.AccessToken,
            SoftwareTokenMfaSettings: {
              Enabled: true,
              PreferredMfa: true,
            },
          };

          const mfaCommand = new SetUserMFAPreferenceCommand(mfaParams);
          await this.cognitoClient.send(mfaCommand);
        } catch (mfaError) {
          // Log the error but don't fail the authentication
          console.error('Failed to set MFA preferences:', mfaError);
        }
      }

      return {
        accessToken: result.AuthenticationResult?.AccessToken,
        refreshToken: result.AuthenticationResult?.RefreshToken,
        idToken: result.AuthenticationResult?.IdToken,
      };
    } catch (error) {
      this.handleCognitoError(error);
    }
  }

  async respondToMFAChallenge(session: string, totpCode: string, email: string) {
    const params = {
      ClientId: this.clientId,
      ChallengeName: ChallengeNameType.SOFTWARE_TOKEN_MFA,
      Session: session,
      ChallengeResponses: {
        USERNAME: email,
        SOFTWARE_TOKEN_MFA_CODE: totpCode,
        SECRET_HASH: this.generateSecretHash(email),
      },
    };

    try {
      const command = new RespondToAuthChallengeCommand(params);
      const result = await this.cognitoClient.send(command);

      return {
        accessToken: result.AuthenticationResult?.AccessToken,
        refreshToken: result.AuthenticationResult?.RefreshToken,
        idToken: result.AuthenticationResult?.IdToken,
      };
    } catch (error) {
      this.handleCognitoError(error);
    }
  }

   /**
   * Initiate forgot password flow
   */
   async forgotPassword(email: string) {
    try {
      const secretHash = this.generateSecretHash(email);
      
      const command = new ForgotPasswordCommand({
        ClientId: this.clientId,
        Username: email,
        SecretHash: secretHash,
      });

      const response = await this.cognitoClient.send(command);
      return response;
    } catch (error) {
      this.handleCognitoError(error);
    }
  }

  /**
   * Confirm new password with confirmation code
   */
  async confirmForgotPassword(email: string, password: string, confirmationCode: string) {
    try {
      const secretHash = this.generateSecretHash(email);
      
      const command = new ConfirmForgotPasswordCommand({
        ClientId: this.clientId,
        Username: email,
        Password: password,
        ConfirmationCode: confirmationCode,
        SecretHash: secretHash,
      });

      const response = await this.cognitoClient.send(command);
      return response;
    } catch (error) {
      this.handleCognitoError(error);
    }
  }

  /**
   * Change user password
   */
  async changePassword(email: string, currentPassword: string, newPassword: string) {
    try {
      // First authenticate the user with current password
      const authResponse = await this.signIn(email, currentPassword);
      
      if (!authResponse?.accessToken) {
        throw new Error('Authentication failed');
      }
      
      const { accessToken } = authResponse;
      
      // Change password using the access token
      const command = new ChangePasswordCommand({
        AccessToken: accessToken,
        PreviousPassword: currentPassword,
        ProposedPassword: newPassword,
      });

      const response = await this.cognitoClient.send(command);
      return response;
    } catch (error) {
      this.handleCognitoError(error);
    }
  }

  /**
   * Sign out a user from all devices (global sign-out)
   * Handles revoking refresh tokens and stopping new token issuance
   * @param accessToken The user's current access token
   */
  async globalSignOut(accessToken: string) {
    try {
      const command = new GlobalSignOutCommand({
        AccessToken: accessToken,
      });

      const response = await this.cognitoClient.send(command);

      // Add the token to our local revocation list
      await this.tokenRevocationService.revokeToken(accessToken);
      

      return response;
    } catch (error) {
      this.handleCognitoError(error);
    }
  }

  /**
   * Sign out a user from all devices by admin
   * Only for admin use - requires admin credentials
   * @param username The user's email/username
   */
  async forcedGlobalSignOut(email: string) {
    try {
      const command = new AdminUserGlobalSignOutCommand({
        UserPoolId: this.userPoolId,
        Username: email,
      });

      const response = await this.cognitoClient.send(command);

      // todo: set the forcedSignOut flag to true for the user

      return response;
    } catch (error) {
      this.handleCognitoError(error);
    }
  }

  /**
   * Refresh a user's access token using a refresh token
   * @param refreshToken The user's refresh token
   * @returns The new access token and refresh token
   */
  async refreshToken(refreshToken: string) {
    try {
   
      const command = new InitiateAuthCommand({
        AuthFlow: 'REFRESH_TOKEN_AUTH',
        ClientId: this.clientId,
        AuthParameters: {
          REFRESH_TOKEN: refreshToken,
          SECRET_HASH: this.clientSecret ,
        },
      });



      const response = await this.cognitoClient.send(command);
      return response;
    } catch (error) {
      this.handleCognitoError(error);
    }
  }

  
}