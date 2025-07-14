import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-jwt';
import * as passportJwt from 'passport-jwt';
const ExtractJwt = passportJwt.ExtractJwt;
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from '../entity/user.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    @InjectRepository(User) private usersRepository: Repository<User>) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: 'my_jwt_secret',
    });
  }
  async validate(payload: any) {
    const user = await this.usersRepository.findOne({ where: { id: payload.sub } });
    if (!user) {
      throw new UnauthorizedException();
    }
    return {
      id: user.id,
      email: user.email,
      role: user.role,
      firstName: user.firstName,
      lastName: user.lastName,
    };
  }
}