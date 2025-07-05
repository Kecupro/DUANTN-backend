var mongoose = require("mongoose");
let orderSchema = new mongoose.Schema(
  {
    user_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "users",
    },
    voucher_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "vouchers",
      default: null,
    },
    address_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "address",
      default: null,
    },
    payment_method_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "payment_methods",
      default: null,
    },
    note: {
      type: String,
      default: null,
      trim: true,
    },
    shipping_fee: {
      type: Number,
      default: 0,
      min: 0,
    },
    total_amount: {
      type: Number,
      required: true,
      min: 0,
    },
    discount_amount: {
      type: Number,
      default: 0,
      min: 0,
    },
    order_status: {
      type: String,
      enum: ["pending", "processing", "shipped", "delivered", "cancelled"],
      required: true,
      default: "pending",
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
  { collection: "orders" }
);

module.exports = orderSchema;
