import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/registerUser.dto';
import { LoginDto } from './dto/loginUser.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  register(@Body() registerDto: RegisterDto) {
    const token = this.authService.registerUser(registerDto);
    return token;
  }

  @Post('login')
  login(@Body() loginDto: LoginDto) {
    const token = this.authService.loginUser(loginDto);
    return token;
  }
}
