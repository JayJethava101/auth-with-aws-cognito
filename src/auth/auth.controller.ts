import { Body, Controller, Post, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignUpDto } from './dto/signup.dto';
import { ConfirmSignUpDto } from './dto/confirm-signup.dto';
import { SignInDto } from './dto/signin.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { JwtGuard } from '../guards/jwt/jwt.guard';
import { GlobalSignOutDto } from './dto/global-signout.dto';
import { ForcedGlobalSignOutDto } from './dto/forced-global-signout.dto';
import { RolesGuard } from '../guards/roles/roles.guard';
import { Roles } from '../decorators/roles.decorator';
import { RefreshTokenDto } from './dto/refresh-token.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  async signUp(@Body() signUpDto: SignUpDto) {
    return this.authService.signUp(signUpDto);
  }

  @Post('confirm-signup')
  async confirmSignUp(@Body() confirmSignUpDto: ConfirmSignUpDto) {
    return this.authService.confirmSignUp(confirmSignUpDto);
  }

  @Post('signin')
  async signIn(@Body() signInDto: SignInDto) {
    return this.authService.signIn(signInDto);
  }

  @Post('forgot-password')
  async forgotPassword(@Body('email') email: string) {
    return this.authService.forgotPassword(email);
  }

  @Post('confirm-forgot-password')
  async confirmForgotPassword(
    @Body('email') email: string,
    @Body('password') password: string,
    @Body('confirmationCode') confirmationCode: string,
  ) {
    return this.authService.confirmForgotPassword(email, password, confirmationCode);
  }

  @UseGuards(JwtGuard)
  @Post('change-password')
  async changePassword(@Body() changePasswordDto: ChangePasswordDto) {
    return this.authService.changePassword(changePasswordDto);
  }

  @UseGuards(JwtGuard)
  @Post('global-signout')
  async globalSignOut(@Body() globalSignOutDto: GlobalSignOutDto) {
    return this.authService.globalSignOut(globalSignOutDto);
  }

  @UseGuards(JwtGuard, RolesGuard)
  @Roles('admin')
  @Post('forced-global-signout')
  async globalSignOutByAdmin(@Body() adminGlobalSignOutDto: ForcedGlobalSignOutDto) {
    return this.authService.forcedGlobalSignOut(adminGlobalSignOutDto);
  }

  @Post('refresh-token')
  async refreshToken(@Body() refreshTokenDto: RefreshTokenDto) {
    return this.authService.refreshToken(refreshTokenDto.refreshToken);
  }
}