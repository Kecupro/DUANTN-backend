const jwt = require("jsonwebtoken");
require("dotenv").config();

const verifyToken = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Token không tồn tại" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // { id, role }
    next();
  } catch (err) {
    return res.status(403).json({ message: "Token không hợp lệ" });
  }
};

// Phân quyền admin
const isAdmin = (req, res, next) => {
  if (req.user.role !== "1") {
    return res.status(403).json({ message: "Không có quyền admin" });
  }
  next();
};

module.exports = { verifyToken, isAdmin };
