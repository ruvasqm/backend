export default interface User {
  _id: string;
  name: string;
  surName: string;
  DateOfBirth: Date;
  password: string;
  twoFactorAuthenticationCode: string;
  isTwoFactorAuthenticationEnabled: boolean;
}
