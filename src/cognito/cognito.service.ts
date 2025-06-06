import { Injectable, BadRequestException, UnauthorizedException } from '@nestjs/common';
import * as crypto from 'crypto';
import { ConfigService } from '@nestjs/config';
import {
  CognitoIdentityProviderClient,
  SignUpCommand,
  InitiateAuthCommand,
  ConfirmSignUpCommand,
  RespondToAuthChallengeCommand,
  AssociateSoftwareTokenCommand,
  VerifySoftwareTokenCommand,
  SetUserMFAPreferenceCommand,
  AuthFlowType,
  ChallengeNameType,
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

@Injectable()
export class CognitoService {
  private readonly cognitoClient: CognitoIdentityProviderClient;
  private readonly userPoolId: string;
  private readonly clientId: string;
  private readonly clientSecret: string;

  constructor(private configService: ConfigService) {
    this.userPoolId = this.configService.get<string>('AWS_COGNITO_USER_POOL_ID') || '';
    this.clientId = this.configService.get<string>('AWS_COGNITO_CLIENT_ID') || '';
    this.clientSecret = this.configService.get<string>('AWS_COGNITO_CLIENT_SECRET') || '';
    
    this.cognitoClient = new CognitoIdentityProviderClient({
      region: this.configService.get<string>('AWS_REGION'),
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
      ],
    };

    try {
      const command = new SignUpCommand(params);
      const result = await this.cognitoClient.send(command);
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
      return { message: 'Email verification successful' };
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
}