import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { verify } from 'jsonwebtoken';
import { Request } from 'express';
import jwkToPem from 'jwk-to-pem';
import axios from 'axios';
import { TokenRevocationService } from 'src/utils/token.revocation.service';

@Injectable()
export class JwtGuard implements CanActivate {
  private cognitoIssuer: string;
  private jwks: any;

  constructor(private configService: ConfigService, 
    private tokenRevocationService: TokenRevocationService,
    ){
    const userPoolId = this.configService.get<string>('AWS_COGNITO_USER_POOL_ID');
    const region = this.configService.get<string>('AWS_REGION');
    this.cognitoIssuer = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;
    
    // Load JWKS on startup
    this.loadJwks();
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }

  private async loadJwks() {
    try {
      const response = await axios.get(`${this.cognitoIssuer}/.well-known/jwks.json`);
      this.jwks = response.data.keys;
    } catch (error) {
      console.error('Failed to load JWKS:', error);
    }
  }

  private getPublicKey(kid: string) {
    if (!this.jwks) {
      throw new Error('JWKS not loaded');
    }
    
    const key = this.jwks.find((k) => k.kid === kid);
    if (!key) {
      throw new Error('Key not found');
    }
    
    return jwkToPem(key);
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    const token = this.extractTokenFromHeader(request);
    
    if (!token) {
      throw new UnauthorizedException('No token provided');
    }

     // First, check if the token has been revoked
     const isRevoked = await this.tokenRevocationService.isTokenRevoked(token);
     if (isRevoked) {
       throw new UnauthorizedException('Session expired, Login again');
     }

    try {
      // Get the header to extract the kid
      const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64').toString());
      const publicKey = this.getPublicKey(header.kid);
      
      const payload = verify(token, publicKey, {
        issuer: this.cognitoIssuer,
        algorithms: ['RS256'],
      });
      
      // Attach user to request object
      request['user'] = payload;
      return true;
    } catch (error) {
      throw new UnauthorizedException('Invalid token');
    }
  }

  
}