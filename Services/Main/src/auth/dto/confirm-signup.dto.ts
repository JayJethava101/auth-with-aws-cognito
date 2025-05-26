import { IsEmail, IsNotEmpty } from 'class-validator';

export class ConfirmSignUpDto {
  @IsEmail()
  email: string;

  @IsNotEmpty()
  confirmationCode: string;
}