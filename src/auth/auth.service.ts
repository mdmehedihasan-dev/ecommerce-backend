import { InjectModel } from '@nestjs/mongoose';
import { User } from 'src/users/user.schema';
import * as bcrypt from 'bcrypt';
import { Model } from 'mongoose';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private jwtService: JwtService
  ) {}

  async register(email: string, password: string): Promise<User> {
    const hashPassword = await bcrypt.hash(password, 10);
    const user = new this.userModel({ email, password: hashPassword } as Partial<User>);
    return user.save();
  }

  async login(email: string, password: string): Promise<{ accessToken: string; refreshToken: string }> {
    const user = await this.userModel.findOne({ email }); // ✅ Fix: fetch user from DB

    if (!user || !(await bcrypt.compare(password, user.password))) { // ✅ Fix: correct password check
      throw new UnauthorizedException("Invalid credentials");
    }

    const payload = { email: user.email, sub: user._id };
    const accessToken = this.jwtService.sign(payload);
    const refreshToken = this.jwtService.sign(payload, { expiresIn: '7d' });

    user.refreshToken = refreshToken; // ✅ Fix: typo 'usee' → 'user'
    await user.save();

    return { accessToken, refreshToken };
  }
}
