var mongoose = require("mongoose");
let addressSchema = new mongoose.Schema(
  {
    user_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "users",
      required: true,
    },

    receiver_name: {
      type: String,
      require: true,
    },

    phone: {
      type: Number,
      require: true,
    },

    address: {
      type: String,
      require: true,
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
  { collection: "address" }
);

module.exports = addressSchema;
