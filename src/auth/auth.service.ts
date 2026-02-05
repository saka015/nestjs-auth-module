import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UserService } from 'src/user/user.service';
import { RegisterDto } from './dto/registerUser.dto';
import bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { LoginDto } from './dto/loginUser.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
  ) {}

  async registerUser(registerUserDto: RegisterDto) {
    const saltRounds = 10;
    const hash = await bcrypt.hash(registerUserDto.password, saltRounds);

    const user = await this.userService.createUser({
      ...registerUserDto,
      password: hash,
    });

    const payload = { sub: user._id };
    const token = await this.jwtService.signAsync(payload);

    return { token: token };
  }
  async loginUser(loginUserDto: LoginDto) {
    const user = await this.userService.findByEmail(loginUserDto.email);
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isPasswordValid = await bcrypt.compare(
      loginUserDto.password,
      user.password,
    );

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const payload = { sub: user._id.toString() };

    return {
      access_token: await this.jwtService.signAsync(payload),
    };
  }
}
