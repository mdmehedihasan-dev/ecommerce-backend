import { InjectModel } from "@nestjs/mongoose";
import { User } from "src/users/user.schema";
import * as bcrypt from 'bcrypt';
import { Model } from 'mongoose';
import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
    constructor(@InjectModel(User.name) private userModel: Model<User>,
    private jwtService: JwtService
    ){}
    async register(email: string, password: string): Promise<User> {
        const hashPassword = await bcrypt.hash(password, 10);
        const user = new this.userModel({ email:email, password: hashPassword });
        return user.save();
    }
}
