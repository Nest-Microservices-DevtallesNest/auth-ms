import { PrismaClient } from '@prisma/client';

import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { LoginUserDto } from './dto/login-user.dto';
import { RegisterUserDto } from './dto';
import { RpcException } from '@nestjs/microservices';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  constructor(private readonly jwtService: JwtService) {
    super();
  }

  private readonly logger = new Logger('AuthService');

  async signJWT(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }

  onModuleInit() {
    this.$connect();
    this.logger.log('MongoDB connected');
  }
  async registerUser(registerUser: RegisterUserDto) {
    const { email, name, password } = registerUser;
    try {
      const user = await this.user.findUnique({
        where: { email: email },
      });

      if (user) {
        throw new RpcException({
          status: 400,
          message: 'User already exists',
        });
      }

      const newUser = await this.user.create({
        data: { email, password: bcrypt.hashSync(password, 10), name },
      });

      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password: _, ...rest } = newUser;

      return {
        user: rest,
        token: await this.signJWT(rest),
      };
    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message,
      });
    }
  }

  async loginUser(loginUserDto: LoginUserDto) {
    const { email, password } = loginUserDto;
    try {
      const user = await this.user.findUnique({
        where: { email: email },
      });

      if (!user) {
        throw new RpcException({
          status: 400,
          message: 'User/Password no valid',
        });
      }

      const isPasswordValid = bcrypt.compareSync(password, user.password);

      if (!isPasswordValid) {
        throw new RpcException({
          status: 400,
          message: 'User/Password no valid',
        });
      }

      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password: _, ...rest } = user;

      return {
        user: rest,
        token: await this.signJWT(rest),
      };
    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message,
      });
    }
  }

  verifyToken() {
    return 'Verify';
  }
}
