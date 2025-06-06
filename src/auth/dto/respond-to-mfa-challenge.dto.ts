import { IsString, IsNotEmpty, IsEmail } from 'class-validator';

export class RespondToMfaChallengeDto {
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @IsNotEmpty()
  session: string;

  @IsString()
  @IsNotEmpty()
  totpCode: string;
} 