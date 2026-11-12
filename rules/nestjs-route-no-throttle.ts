// Test cases for nestjs-route-no-throttle and nestjs-global-throttler. Run: opengrep scan --test rules/
import { Controller, Post, Body, UseGuards, Get, Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { Throttle, ThrottlerGuard } from '@nestjs/throttler';

@Controller('auth')
export class AuthController {
  // ruleid: nestjs-route-no-throttle
  @Post('login')
  async login(@Body() dto: LoginDto) {
    return this.auth.login(dto);
  }

  // ruleid: nestjs-route-no-throttle
  @Post('reset-password')
  reset(@Body() dto: ResetDto) {}

  // ok: nestjs-route-no-throttle
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @Post('register')
  register(@Body() dto: RegisterDto) {}

  // ok: nestjs-route-no-throttle
  @UseGuards(ThrottlerGuard)
  @Post('verify')
  verify() {}

  // Reading, not submitting.
  // ok: nestjs-route-no-throttle
  @Get('login')
  page() {}

  // ok: nestjs-route-no-throttle
  @Post('profile')
  update() {}
}

@Controller('sign-up')
export class SignupController {
  // ruleid: nestjs-route-no-throttle
  @Post()
  create() {}
}

@UseGuards(ThrottlerGuard)
@Controller('otp')
export class OtpController {
  // ok: nestjs-route-no-throttle
  @Post('verify')
  verify() {}
}

@Module({
  providers: [
    // ruleid: nestjs-global-throttler
    { provide: APP_GUARD, useClass: ThrottlerGuard },
  ],
})
export class AppModule {}
