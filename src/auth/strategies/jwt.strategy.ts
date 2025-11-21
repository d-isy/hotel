import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { UserService } from '../../user/user.service';
import { JwtPayload } from '../interfaces/jwt-payload.interface';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private readonly userService: UserService,
    private readonly configService: ConfigService,
  ) {
    super({
      // Extraer el token del header Authorization como Bearer token
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      // No ignorar la expiración del token
      ignoreExpiration: false,
      // Secreto para verificar el token
      secretOrKey: configService.get('JWT_SECRET'),
    });
  }

  /**
   * Método que se ejecuta automáticamente después de validar el token
   * El payload ya viene decodificado por Passport
   */
  async validate(payload: JwtPayload) {
    const { sub: id } = payload;

    // Buscar el usuario en la base de datos
    const user = await this.userService.findOne(id);

    // Verificar si el usuario está activo
    if (!user.isActive) {
      throw new UnauthorizedException('Usuario inactivo');
    }

    // Retornar el usuario (se agregará a request.user)
    return user;
  }
}