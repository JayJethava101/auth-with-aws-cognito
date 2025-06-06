import { IsString, IsNotEmpty } from 'class-validator';

export class VerifyTotpDto {
  @IsString()
  @IsNotEmpty()
  session: string;

  @IsString()
  @IsNotEmpty()
  totpCode: string;
} 