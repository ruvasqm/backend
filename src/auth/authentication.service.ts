import * as bcrypt from "bcrypt";
import { Response } from "express";
import * as jwt from "jsonwebtoken";
import * as QRCode from "qrcode";
import * as speakeasy from "speakeasy";
import UserWithThatEmailAlreadyExistsException from "../exceptions/UserWithThatEmailAlreadyExistsException";
import DataStoredInToken from "../interfaces/dataStoredInToken";
import TokenData from "../interfaces/tokenData.interface";
import CreateUserDto from "../user/CreateUser.dto";
import User from "../user/user.interface";
import userModel from "./../user/user.model";
import LogInDto from "./logIn.dto";

class AuthenticationService {
  public user = userModel;

  public async register(userData: CreateUserDto) {
    if (await Promise.resolve(this.user.findOne({ email: userData.email }))) {
      throw new UserWithThatEmailAlreadyExistsException(userData.email);
    }
    const hashedPassword = await bcrypt.hash(userData.password, 10);
    const user = await this.user.create({
      ...userData,
      password: hashedPassword,
    });
    user.password = undefined;
    const tokenData = this.createToken(user);
    const cookie = this.createCookie(tokenData);
    return {
      cookie,
      user,
    };
  }

  public async unregister(userData: LogInDto) {
    const user = await Promise.resolve(
      this.user.deleteOne({
        email: userData.email,
      })
    );
    return { message: "Account deleted succesfully" };
  }

  public getTwoFactorAuthenticationCode() {
    const secretCode = speakeasy.generateSecret({
      name: process.env.TWO_FACTOR_AUTHENTICATION_APP_NAME,
    });
    return {
      otpauthUrl: secretCode.otpauth_url,
      base32: secretCode.base32,
    };
  }
  public verifyTwoFactorAuthenticationCode(
    twoFactorAuthenticationCode: string,
    user: User
  ) {
    return speakeasy.totp.verify({
      secret: user.twoFactorAuthenticationCode,
      encoding: "base32",
      token: twoFactorAuthenticationCode,
    });
  }
  public async respondWithQRCode(data: string, response: Response) {
    console.log(await Promise.resolve(QRCode.toDataURL(data)));
    QRCode.toFileStream(response, data);
  }
  public createCookie(tokenData: TokenData) {
    return `Authorization=${tokenData.token}; HttpOnly; Max-Age=${tokenData.expiresIn}`;
  }
  public createToken(
    user: User,
    isSecondFactorAuthenticated = false
  ): TokenData {
    const expiresIn = 60 * 60; // an hour
    const secret = process.env.JWT_SECRET;
    console.log(isSecondFactorAuthenticated);
    const dataStoredInToken: DataStoredInToken = {
      isSecondFactorAuthenticated,
      _id: user._id,
    };
    return {
      expiresIn,
      token: jwt.sign(dataStoredInToken, secret, { expiresIn }),
    };
  }
}

export default AuthenticationService;
