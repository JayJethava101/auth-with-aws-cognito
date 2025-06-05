import { Global, Injectable } from '@nestjs/common';
import { InjectRedis } from '@nestjs-modules/ioredis';
import { Redis } from 'ioredis';
import { jwtDecode } from 'jwt-decode';

@Global()
@Injectable()
export class TokenRevocationService {
  constructor(
    @InjectRedis() private readonly redis: Redis,
  ) {}

  // When a user signs out, add their token to the blacklist
  async revokeToken(token: string): Promise<void> {
    const decodedToken = jwtDecode(token);
    const expiryTimeInSeconds = ( decodedToken.exp || 0 )- Math.floor(Date.now() / 1000);
    
    // Only add to revocation list if token is not already expired
    if (expiryTimeInSeconds > 0) {
      await this.redis.set(`revoked:${token}`, '1', 'EX', expiryTimeInSeconds);
    }
    
  }

  // Check if a token has been revoked
  async isTokenRevoked(token: string): Promise<boolean> {
    const result = await this.redis.get(`revoked:${token}`);
    return result === '1';
  }
}