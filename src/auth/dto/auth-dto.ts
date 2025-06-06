// 3. DTOs with class-validator
import { IsEmail, IsString, IsNotEmpty, MinLength, MaxLength, Matches } from 'class-validator';

export class SignUpDto {
  @IsEmail({}, { message: 'Please provide a valid email address' })
  @IsNotEmpty({ message: 'Email is required' })
  email: string;

  @IsString({ message: 'Password must be a string' })
  @IsNotEmpty({ message: 'Password is required' })
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, {
    message: 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
  })
  password: string;

  @IsString({ message: 'Name must be a string' })
  @IsNotEmpty({ message: 'Name is required' })
  @MinLength(2, { message: 'Name must be at least 2 characters long' })
  @MaxLength(50, { message: 'Name must not exceed 50 characters' })
  name: string;
}

export class ConfirmSignUpDto {
  @IsEmail({}, { message: 'Please provide a valid email address' })
  @IsNotEmpty({ message: 'Email is required' })
  email: string;

  @IsString({ message: 'Confirmation code must be a string' })
  @IsNotEmpty({ message: 'Confirmation code is required' })
  @Matches(/^\d{6}$/, { message: 'Confirmation code must be exactly 6 digits' })
  confirmationCode: string;
}

export class SignInDto {
  @IsEmail({}, { message: 'Please provide a valid email address' })
  @IsNotEmpty({ message: 'Email is required' })
  email: string;

  @IsString({ message: 'Password must be a string' })
  @IsNotEmpty({ message: 'Password is required' })
  password: string;
}

export class VerifyMFADto {
  @IsEmail({}, { message: 'Please provide a valid email address' })
  @IsNotEmpty({ message: 'Email is required' })
  email: string;

  @IsString({ message: 'Session must be a string' })
  @IsNotEmpty({ message: 'Session is required' })
  session: string;

  @IsString({ message: 'TOTP code must be a string' })
  @IsNotEmpty({ message: 'TOTP code is required' })
  @Matches(/^\d{6}$/, { message: 'TOTP code must be exactly 6 digits' })
  totpCode: string;
}

export class SetupMFADto {
  @IsString({ message: 'Session must be a string' })
  @IsNotEmpty({ message: 'Session is required' })
  session: string;
}

export class VerifyMFASetupDto {
  @IsString({ message: 'Session must be a string' })
  @IsNotEmpty({ message: 'Session is required' })
  session: string;

  @IsString({ message: 'TOTP code must be a string' })
  @IsNotEmpty({ message: 'TOTP code is required' })
  @Matches(/^\d{6}$/, { message: 'TOTP code must be exactly 6 digits' })
  totpCode: string;
}