import * as mongoose from "mongoose";
import User from "./user.interface";

const userSchema = new mongoose.Schema({
  name: String,
  surName: String,
  DateOfBirth: Date,
  password: String,
  twoFactorAuthenticationCode: String,
  isTwoFactorAuthenticationEnabled: Boolean,
});

const userModel = mongoose.model<User & mongoose.Document>("User", userSchema);

export default userModel;
