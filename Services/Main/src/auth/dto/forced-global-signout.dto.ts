import { IsString, IsNotEmpty, IsEmail } from 'class-validator';

export class ForcedGlobalSignOutDto {
  @IsString()
  @IsEmail()
  @IsNotEmpty()
  username: string;
} 