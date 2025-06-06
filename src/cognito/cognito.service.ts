import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { jwtDecode } from 'jwt-decode';
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
} from '@aws-sdk/client-cognito-identity-provider';
import { createHmac } from 'crypto';
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
   * Calculate the secret hash for AWS Cognito
   */
  private calculateSecretHash(username: string): string {
    // if (!this.clientSecret) return null;
    
    return createHmac('sha256', this.clientSecret)
      .update(username + this.clientId)
      .digest('base64');
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

  /**
   * Sign up a new user
   */
  async signUp(email: string, password: string, userAttributes: { Name: string; Value: string }[]) {
    try {
      const secretHash = this.calculateSecretHash(email);
      
      const command = new SignUpCommand({
        ClientId: this.clientId,
        Username: email,
        Password: password,
        SecretHash: secretHash,
        UserAttributes: userAttributes,
      });

      const response = await this.cognitoClient.send(command);
      return response;
    } catch (error) {
      this.handleCognitoError(error);
    }
  }

  /**
   * Confirm sign up with verification code
   */
  async confirmSignUp(email: string, confirmationCode: string) {
    try {
      const secretHash = this.calculateSecretHash(email);
      
      const command = new ConfirmSignUpCommand({
        ClientId: this.clientId,
        Username: email,
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
   * Sign in a user
   */
  async signIn(email: string, password: string) {
    try {
      const secretHash = this.calculateSecretHash(email);
      
      const command = new InitiateAuthCommand({
        AuthFlow: 'USER_PASSWORD_AUTH',
        ClientId: this.clientId,
        AuthParameters: {
          USERNAME: email,
          PASSWORD: password,
          SECRET_HASH: secretHash,
        },
      });

      const response = await this.cognitoClient.send(command);
      return response;
    } catch (error) {
      this.handleCognitoError(error);
    }
  }

  /**
   * Initiate forgot password flow
   */
  async forgotPassword(email: string) {
    try {
      const secretHash = this.calculateSecretHash(email);
      
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
      const secretHash = this.calculateSecretHash(email);
      
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
      
      if (!authResponse.AuthenticationResult) {
        throw new Error('Authentication failed');
      }
      
      const { AccessToken } = authResponse.AuthenticationResult;
      
      // Change password using the access token
      const command = new ChangePasswordCommand({
        AccessToken,
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
  async forcedGlobalSignOut(username: string) {
    try {
      const command = new AdminUserGlobalSignOutCommand({
        UserPoolId: this.userPoolId,
        Username: username,
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

  /**
   * Initiate MFA setup for a user
   * @param session The session from confirm signup
   * @returns The secret code for TOTP setup and new session
   */
  async initiateMfaSetup(session: string) {
    try {
      const command = new AssociateSoftwareTokenCommand({
        Session: session,
      });

      const response = await this.cognitoClient.send(command);
      return response;
    } catch (error) {
      this.handleCognitoError(error);
    }
  }

  /**
   * Verify TOTP token during MFA setup
   * @param session The session from initiate-mfa-setup
   * @param totpCode The TOTP code to verify
   * @returns The verification status and new session
   */
  async verifyTotp(session: string, totpCode: string) {
    try {
      console.log('totpCode', totpCode);
      const command = new VerifySoftwareTokenCommand({
        Session: session,
        UserCode: totpCode,
      });

      const response = await this.cognitoClient.send(command);
      return response;
    } catch (error) {
      this.handleCognitoError(error);
    }
  }

  /**
   * Enable MFA for a user after successful verification
   * @param accessToken The user's access token
   */
  async enableMfa(accessToken: string) {
    try {
      const command = new SetUserMFAPreferenceCommand({
        AccessToken: accessToken,
        SoftwareTokenMfaSettings: {
          Enabled: true,
          PreferredMfa: true,
        },
      });

      const response = await this.cognitoClient.send(command);
      return response;
    } catch (error) {
      this.handleCognitoError(error);
    }
  }

  /**
   * Respond to MFA challenge during sign in
   * @param email The user's email
   * @param session The session from verify-totp
   * @param totpCode The TOTP code to verify
   * @returns The authentication result with tokens
   */
  async respondToMfaChallenge(email: string, session: string, totpCode: string) {
    try {
      const command = new RespondToAuthChallengeCommand({
        ChallengeName: 'SOFTWARE_TOKEN_MFA',
        ClientId: this.clientId,
        Session: session,
        ChallengeResponses: {
          SOFTWARE_TOKEN_MFA_CODE: totpCode,
          USERNAME: email,
          SECRET_HASH: this.calculateSecretHash(email),
        },
      });

      const response = await this.cognitoClient.send(command);
      return response;
    } catch (error) {
      this.handleCognitoError(error);
    }
  }

  /**
   * Helper method to get username from session
   * @param session The session token
   * @returns The username
   */
  private getUsernameFromSession(session: string): string {
    // You might need to implement this based on your session structure
    // This is a placeholder implementation
    return '';
  }
}