var mongoose = require("mongoose");
let userSchema = new mongoose.Schema(
  {
    googleId: {
      type: String,
      unique: true,
      sparse: true // Cho phép nhiều document có giá trị null
    },
    facebookId: {
      type: String,
      unique: true,
      sparse: true 
    },
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
    },
    password_hash: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
    },
    emailVerificationCode: {
      type: String,
      default: null,
    },
    emailVerificationCodeExpires: {
      type: Date,
      default: null,
    },
    passwordResetToken: {
      type: String,
      default: null,
    },
    passwordResetTokenExpires: {
      type: Date,
      default: null,
    },
    account_status: {
      type: String,
      enum: ["0", "1"], // 0 = unverified, 1 = verified
      default: "0",
      required: true,
    },
    role: {
      type: String,
      enum: ["0", "1", "2"], // 0=user, 1=admin, 2=super_admin
      default: "0",
      required: true,
    },
    avatar: {
      type: String,
      default: null,
    },
    created_at: {
      type: Date,
      default: Date.now,
    },
    updated_at: {
      type: Date,
      default: Date.now,
    },
  },
  {
    collection: "users",
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

userSchema.virtual("addresses", {
  ref: "address",
  localField: "_id",
  foreignField: "user_id",
});

userSchema.set("toObject", { virtuals: true });
userSchema.set("toJSON", { virtuals: true });

module.exports = userSchema;
