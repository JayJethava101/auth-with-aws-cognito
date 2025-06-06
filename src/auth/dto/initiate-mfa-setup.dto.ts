import { IsString, IsNotEmpty, IsEmail } from 'class-validator';

export class InitiateMfaSetupDto {
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @IsNotEmpty()
  session: string;
} 