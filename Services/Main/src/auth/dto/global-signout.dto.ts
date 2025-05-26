import { IsString, IsNotEmpty } from 'class-validator';

export class GlobalSignOutDto {
  @IsString()
  @IsNotEmpty()
  accessToken: string;
} 