require('dotenv').config();
const exp = require('express');
const app = exp();
const port = 3000;
const cors = require('cors');
const multer = require('multer');
//app.use( [ cors() , exp.json() ] );
app.use( exp.json() );
app.use(cors({
    origin: "http://localhost:3005", 
    credentials: true 
}));

// ! Lưu ảnh danh mục sản phẩm
const storageCateProduct = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = path.join(
      __dirname,
      "..",
      "DATN",
      "public",
      "images",
      "images_DATN",
      "category"
    );
    fs.mkdirSync(uploadDir, { recursive: true });
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    const fileExtension = path.extname(file.originalname);
    cb(null, file.fieldname + "-" + uniqueSuffix + fileExtension);
  },
});
const uploadCateProduct = multer({ storage: storageCateProduct });

// ! Lưu ảnh thương hiệu
const storageBrand = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = path.join(
      __dirname,
      "..",
      "DATN",
      "public",
      "images",
      "images_DATN",
      "brand"
    );
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    const fileExtension = path.extname(file.originalname);
    cb(null, file.fieldname + "-" + uniqueSuffix + fileExtension);
  },
});
const uploadBrand = multer({ storage: storageBrand });

// ! Lưu ảnh thương hiệu
const storageNew = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = path.join(
      __dirname,
      "..",
      "DATN",
      "public",
      "images",
      "images_DATN",
      "news"
    );
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    const fileExtension = path.extname(file.originalname);
    cb(null, file.fieldname + "-" + uniqueSuffix + fileExtension);
  },
});
const uploadNew = multer({ storage: storageNew });

// // ! Lưu ảnh sản phẩm
// const storage = multer.diskStorage({
//   destination: function (req, file, cb) {
//     const uploadDir = path.join(
//       __dirname,
//       "..",
//       "DATN",
//       "public",
//       "images",
//       "images_DATN",
//       "product"
//     );
//     cb(null, uploadDir);
//   },
//   filename: function (req, file, cb) {
//     const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
//     const fileExtension = path.extname(file.originalname);
//     cb(null, file.fieldname + "-" + uniqueSuffix + fileExtension);
//   },
// });

const mongoose = require('mongoose');

// Lấy URI từ biến môi trường, nếu không có thì dùng local
const MONGODB_URI = process.env.DB_URI || 'mongodb://127.0.0.1:27017/DATN_V2';

mongoose.connect(MONGODB_URI);
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
const passport = require('passport');
require('./auth/google'); // import cấu hình passport google
require('./auth/facebook'); // import cấu hình passport facebook
const ObjectId = mongoose.Types.ObjectId;
const conn = mongoose.createConnection(MONGODB_URI);
const newsSchema = require("./model/schemaNews");
const categoryNewsSchema = require("./model/schemaCategoryNews");
const userSchema = require("./model/schemaUser");
const voucherSchema = require("./model/schemaVoucher");
const brandSchema = require("./model/schemaBrand");
const productSchema = require("./model/schemaProduct");
const productImageSchema = require("./model/schemaProductImages");
const productCategoriesSchema = require("./model/schemaproductCategories");
const categorySchema = require("./model/schemaCategory");
const orderSchema = require("./model/schemaOrder");
const orderDetailSchema = require("./model/schemaOrderDetail");
const reviewsSchema = require("./model/schemaReviews");
const wishlistSchema = require("./model/schemaWishlist");
const addressSchema = require("./model/schemaAddress");
const PaymentMethoaShema = require("./model/schemaPaymentMethods");

const NewsModel = conn.model("news", newsSchema);
const CategoryNewsModel = conn.model("category_news", categoryNewsSchema);
const UserModel = conn.model("users", userSchema);
const VoucherModel = conn.model("vouchers", voucherSchema);
const BrandModel = conn.model("brands", brandSchema);
const ProductModel = conn.model("products", productSchema);
const ProductImageModel = conn.model("product_images", productImageSchema);
const ProductCategoriesModel = conn.model("product_categories", productCategoriesSchema);
const CategoryModel = conn.model("categories", categorySchema);
const OrderModel = conn.model("orders", orderSchema);
const OrderDetailModel = conn.model("order_details", orderDetailSchema);
const ReviewModel = conn.model("reviews", reviewsSchema);
const WishlistModel = conn.model("wishlists", wishlistSchema);
const AddressModel = conn.model("address", addressSchema);
const PaymentMethodModel = conn.model("payment_methods", PaymentMethoaShema);


const avatarUploadPath = path.join(__dirname, 'uploads', 'avatars');
if (!fs.existsSync(avatarUploadPath)) {
  fs.mkdirSync(avatarUploadPath, { recursive: true });
}

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, avatarUploadPath);
  },
  filename: function (req, file, cb) {
    cb(null, req.user.userId + '-' + Date.now() + path.extname(file.originalname));
  }
});

const fileFilter = (req, file, cb) => {
  if (file.mimetype === 'image/jpeg' || file.mimetype === 'image/png' || file.mimetype === 'image/gif') {
    cb(null, true);
  } else {
    cb(new Error('Chỉ chấp nhận file ảnh (jpeg, png, gif)'), false);
  }
};

const upload = multer({ 
  storage: storage, 
  limits: { fileSize: 1024 * 1024 * 5 }, 
  fileFilter: fileFilter 
});

app.use('/uploads', exp.static(path.join(__dirname, 'uploads')));

const jwt = require('jsonwebtoken');
const User = mongoose.model('User', userSchema);

const JWT_SECRET = 'ef9acdfacc73cb783301ab499281cdb28098f3100c43df3c3c5f60cfa902abc9'; 

const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Vui lòng đăng nhập' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ message: 'Token không hợp lệ' });
  }
};
const isAdmin = (req, res, next) => {
  if (req.user.role !== '1' && req.user.role !== '2') {
    return res.status(403).json({ message: 'Không có quyền truy cập' });
  }
  next();
};

const isSuperAdmin = (req, res, next) => {
  if (req.user.role !== '2') {
    return res.status(403).json({ message: 'Chỉ Super Admin mới có quyền này' });
  }
  next();
};

const canDeleteUser = (req, res, next) => {
  const targetUserId = req.params.id;
  
  // Super admin có thể xóa tất cả
  if (req.user.role === '2') {
    return next();
  }
  
  // Admin thường không thể xóa ai cả
  return res.status(403).json({ message: 'Chỉ Super Admin mới có quyền xóa người dùng' });
};

app.use(session({
  secret: process.env.JWT_SECRET || 'your_jwt_secret_key',
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

const nodemailer = require('nodemailer');

// Cấu hình transporter cho Nodemailer
// BẠN CẦN THAY THẾ CÁC GIÁ TRỊ NÀY TRONG FILE .env
const transporter = nodemailer.createTransport({
  service: 'gmail', // Hoặc dịch vụ email khác
  auth: {
    user: process.env.EMAIL_USER, // process.env.EMAIL_USER => địa chỉ email của bạn
    pass: process.env.EMAIL_PASS, // process.env.EMAIL_PASS => mật khẩu ứng dụng email của bạn
  },
});

const { body, validationResult } = require('express-validator');

app.post('/register', 
  body('email').isEmail().withMessage('Email không hợp lệ.'),
  body('password').isLength({ min: 6 }).withMessage('Mật khẩu phải có ít nhất 6 ký tự.'),
  body('username').notEmpty().withMessage('Tên tài khoản không được để trống.'),
  async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: errors.array()[0].msg });
    }

    const { username, password, email } = req.body;

    let existUser = await User.findOne({ email });
    if (existUser && existUser.account_status === '1') {
      return res.status(400).json({ message: 'Email đã được sử dụng' });
    }
     existUser = await User.findOne({ username });
    if (existUser) {
      return res.status(400).json({ message: 'Username đã được sử dụng' });
    }

    const saltRounds = 10;
    const password_hash = await bcrypt.hash(password, saltRounds);
    
    // Tạo mã xác thực
    const emailVerificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    const emailVerificationCodeExpires = new Date(Date.now() + 10 * 60 * 1000); // Hết hạn sau 10 phút

    // Nếu email đã tồn tại nhưng chưa xác thực, cập nhật người dùng đó
    let savedUser;
    const existingUnverifiedUser = await User.findOne({ email, account_status: '0' });

    if (existingUnverifiedUser) {
      existingUnverifiedUser.username = username;
      existingUnverifiedUser.password_hash = password_hash;
      existingUnverifiedUser.emailVerificationCode = emailVerificationCode;
      existingUnverifiedUser.emailVerificationCodeExpires = emailVerificationCodeExpires;
      savedUser = await existingUnverifiedUser.save();
    } else {
      // Ngược lại, tạo người dùng mới
      const newUser = new User({
        username,
        password_hash,
        email,
        emailVerificationCode,
        emailVerificationCodeExpires,
        account_status: '0', // 0 = chưa xác thực
        role: '0', // Sửa lại thành '0' thay vì '1'
      });
      savedUser = await newUser.save();
    }

    // Gửi email xác thực
    const mailOptions = {
      from: `"V.CLOCK" <${process.env.EMAIL_USER}>`,
      to: savedUser.email,
      subject: 'Mã xác thực tài khoản V.CLOCK',
      html: `<p>Chào bạn,</p>
             <p>Cảm ơn bạn đã đăng ký tài khoản tại V.CLOCK. Mã xác thực của bạn là:</p>
             <h2 style="text-align:center;color:#d9534f;">${emailVerificationCode}</h2>
             <p>Mã này sẽ hết hạn trong 10 phút.</p>
             <p>Trân trọng,<br/>Đội ngũ V.CLOCK</p>`,
    };

    await transporter.sendMail(mailOptions);

    res.status(201).json({
      message: 'Đăng ký thành công. Vui lòng kiểm tra email để lấy mã xác thực.',
      user: { email: savedUser.email } 
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

app.post('/verify-email', async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ message: 'Vui lòng cung cấp email và mã OTP.' });
    }

    const user = await User.findOne({
      email: email,
      emailVerificationCode: otp,
      emailVerificationCodeExpires: { $gt: Date.now() }, // Kiểm tra mã còn hạn
    });

    if (!user) {
      return res.status(400).json({ message: 'Mã OTP không hợp lệ hoặc đã hết hạn.' });
    }

    user.account_status = '1'; // Cập nhật trạng thái đã xác thực
    user.emailVerificationCode = null; // Xóa mã OTP
    user.emailVerificationCodeExpires = null; // Xóa thời gian hết hạn
    await user.save();
    
    res.status(200).json({ message: 'Xác thực email thành công!' });

  } catch (error) {
    console.error('Verify email error:', error);
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    let user = await User.findOne({
       $or: [{ username: username }, { email: username }] 
      });

    if (!user) {
      return res.status(404).json({ message: 'Tài khoản không tồn tại' });
    }
    //Kiểm tra tài khoản đã xác thực chưa
    if (user.account_status !== '1') {
      return res.status(403).json({ message: 'Tài khoản của bạn chưa được xác thực. Vui lòng kiểm tra email.' });
    }

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(400).json({ message: 'Mật khẩu không đúng' });
    }

    const token = jwt.sign(
      { userId: user._id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '1d' }
    );

    const { password_hash: _, ...userWithoutPassword } = user.toObject();

    res.json({
      
      message: 'Đăng nhập thành công',
      user: userWithoutPassword,
      token
    });
  } catch (error) {
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

app.put('/user/profile/update', verifyToken, upload.single('avatar'), async (req, res) => {
  try {
    const { fullname, email, phone_number, address } = req.body;
    const userId = req.user.userId;

    const userToUpdate = await User.findById(userId);
    if (!userToUpdate) {
      return res.status(404).json({ message: 'Không tìm thấy người dùng' });
    }
    if (email && email !== userToUpdate.email) {
      const existingUserWithNewEmail = await User.findOne({ email: email, _id: { $ne: userId } });
      if (existingUserWithNewEmail) {
        return res.status(400).json({ message: 'Email này đã được sử dụng bởi tài khoản khác.' });
      }
      userToUpdate.email = email;
    }

    if (fullname) userToUpdate.fullname = fullname;
    if (phone_number) userToUpdate.phone_number = phone_number;
    if (address) userToUpdate.address = address;

    if (req.file) {
      // xóa ảnh cũ nếu có
      if (userToUpdate.avatar && userToUpdate.avatar.startsWith('uploads/avatars/')) {
        const oldAvatarPath = path.join(__dirname, userToUpdate.avatar);
        if (fs.existsSync(oldAvatarPath)) {
          try {
            fs.unlinkSync(oldAvatarPath);
          } catch (err) {
            console.error("Failed to delete old avatar:", err);
            return res.status(500).json({ message: 'Lỗi khi xóa ảnh đại diện cũ', error: err.message });
          }
        }
      }
      userToUpdate.avatar = 'uploads/avatars/' + req.file.filename; // Store relative path
    }

    const updatedUser = await userToUpdate.save();

    const { password_hash: _, ...userWithoutPassword } = updatedUser.toObject();
    res.json({
      message: 'Cập nhật thông tin thành công',
      user: userWithoutPassword
    });

  } catch (error) {
    console.error("Update profile error:", error);
    if (error.code === 11000 && error.keyPattern && error.keyPattern.email) {
        return res.status(400).json({ message: 'Email này đã được sử dụng.' });
    }
    if (error.message.includes('Chỉ chấp nhận file ảnh')) {
        return res.status(400).json({ message: error.message });
    }
    res.status(500).json({ message: 'Lỗi server khi cập nhật thông tin', error: error.message });
  }
});

app.get('/user/profile', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'Không tìm thấy người dùng' });
    }
    
    const { password_hash: _, ...userWithoutPassword } = user.toObject();
    res.json(userWithoutPassword);
  } catch (error) {
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

app.get("/", (req, res) => {res.json("{'thongbao':'API NodeJS'}")});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    // Tạo JWT token cho user
    const token = jwt.sign(
      { userId: req.user._id, username: req.user.username, role: req.user.role },
      process.env.JWT_SECRET ,
      { expiresIn: '1d' }
    );
    // Redirect về frontend kèm token
    res.redirect(`http://localhost:3005/auth/google/success?token=${token}`);
  }
);

app.get('/auth/facebook',
  passport.authenticate('facebook', { scope: ['email'] })
);

app.get('/auth/facebook/callback',
  passport.authenticate('facebook', { failureRedirect: '/login', session: false }),
  (req, res) => {
    // Tạo JWT token cho user
    const token = jwt.sign(
      { userId: req.user._id, username: req.user.username, role: req.user.role },
      process.env.JWT_SECRET || 'your_jwt_secret_key',
      { expiresIn: '1d' }
    );
    // Redirect về frontend kèm token
    res.redirect(`http://localhost:3005/auth/google/success?token=${token}`);
  }
);

// Facebook Data Deletion Callback
app.post('/auth/facebook/delete-data', async (req, res) => {
  const signedRequest = req.body.signed_request;
  if (!signedRequest) {
    return res.status(400).send('Invalid request');
  }

  try {
    // 1. Tách và giải mã signed_request
    const [encodedSig, payload] = signedRequest.split('.');
    const sig = Buffer.from(encodedSig.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    const data = JSON.parse(Buffer.from(payload.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString());

    // 2. Xác thực chữ ký
    const crypto = require('crypto');
    const expectedSig = crypto.createHmac('sha256', process.env.FACEBOOK_APP_SECRET).update(payload).digest();

    if (!crypto.timingSafeEqual(sig, expectedSig)) {
      console.error('Facebook Deletion Callback: Invalid signature.');
      return res.status(400).send('Invalid signature');
    }

    // 3. Xóa dữ liệu người dùng
    const userIdToDelete = data.user_id;
    await User.findOneAndDelete({ facebookId: userIdToDelete });

    // 4. Phản hồi cho Facebook
    const confirmationCode = `delete_confirm_${userIdToDelete}`;
    res.json({
      url: `http://localhost:3000/auth/facebook/deletion-status/${confirmationCode}`,
      confirmation_code: confirmationCode,
    });

  } catch (error) {
    console.error('Error processing Facebook data deletion:', error);
    res.status(500).send('An error occurred');
  }
});

// Endpoint để người dùng kiểm tra trạng thái xóa (Facebook yêu cầu)
app.get('/auth/facebook/deletion-status/:confirmation_code', (req, res) => {
    res.setHeader('Content-Type', 'text/html');
    res.send(`
        <html>
            <head><title>Data Deletion Status</title></head>
            <body>
                <h2>Yêu cầu xóa dữ liệu của bạn đã được xử lý.</h2>
                <p>Tất cả dữ liệu liên quan đến tài khoản của bạn trên ứng dụng của chúng tôi đã được xóa thành công.</p>
                <p>Mã xác nhận của bạn: ${req.params.confirmation_code}</p>
            </body>
        </html>
    `);
});

// http://localhost:3000/api/sp
app.get('/api/sp', async function(req, res) {    
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 12;
  const skip = (page - 1) * limit;

  const { category: categoryName, brand: brandName, price_max, sort } = req.query;

  try {
    let query = {};
    let productIds = [];

    // Lọc theo danh mục
    if (categoryName && categoryName !== 'Tất cả') {
      const category = await CategoryModel.findOne({ name: categoryName });
      if (category) {
        const productCategories = await ProductCategoriesModel.find({ category_id: category._id });
        productIds = productCategories.map(pc => pc.product_id);
        query._id = { $in: productIds };
      } else {
        // Nếu không tìm thấy category, trả về mảng rỗng
        return res.json({ list: [], total: 0 });
      }
    }

    // Lọc theo thương hiệu
    if (brandName) {
      const brand = await BrandModel.findOne({ name: brandName });
      if (brand) {
        query.brand_id = brand._id;
      } else {
        // Nếu không tìm thấy brand, trả về mảng rỗng
        return res.json({ list: [], total: 0 });
      }
    }

    // Lọc theo giá
    if (price_max && !isNaN(Number(price_max))) {
      query.price = { $lte: Number(price_max) };
    }

    // Sắp xếp
    let sortOption = { created_at: -1 };
    if (sort) {
      if (sort === 'price-asc') sortOption = { price: 1 };
      if (sort === 'price-desc') sortOption = { price: -1 };
    }

    const total = await ProductModel.countDocuments(query);
    const products = await ProductModel.find(query)
      .populate({
        path: "brand_id",
        model: "brands",
        select: "name",
      })
      .sort(sortOption)
      .skip(skip)
      .limit(limit);

      const list = await Promise.all(
        products.map(async (product) => {
          const main_image = await ProductImageModel.findOne({
            product_id: product._id,
            is_main: true,
          }).select("image alt");
      
          const categoryMap = await ProductCategoriesModel.find({
            product_id: product._id,
          }).populate({
            path: "category_id",
            model: "categories",
            select: "name",
          });
      
          const categories = categoryMap.map((item) => item.category_id);
      
          const sold = await OrderDetailModel.aggregate([
            { $match: { product_id: product._id } },
            { $group: { _id: "$product_id", total: { $sum: "$quantity" } } },
          ]);
      
          const sold_count = sold[0]?.total || 0;
      
          // 👇 Chỗ này đổi brand_id → brand
          const { brand_id, ...productData } = product.toObject();
      
          return {
            ...productData,
            brand: brand_id, // brand_id đã được populate { _id, name }
            main_image,
            categories,
            sold: sold_count,
          };
        })
      );
      

    res.json({ list, total, totalPages: Math.ceil(total / limit) });
  } catch (error) {
    console.error("Lỗi khi truy vấn MongoDB:", error);
    res.status(500).json({ error: "Lỗi khi lấy danh sách sản phẩm." });
  }
});

// http://localhost:3000/api/sp_moi
app.get('/api/sp_moi', async (req, res) => {
  const limit = parseInt(req.query.limit, 10) || 10;

  try {
    const products = await ProductModel.aggregate([
      {
        $lookup: {
          from: 'product_images',
          let: { productId: '$_id' },
          pipeline: [
            {
              $match: {
                $expr: {
                  $and: [
                    { $eq: ['$product_id', '$$productId'] },
                    { $eq: ['$is_main', true] }
                  ]
                }
              }
            },
            {
              $project: {
                image: 1,
                alt: 1,
                _id: 1
              }
            }
          ],
          as: 'main_image'
        }
      },
      {$lookup: {
        from: 'brands',
        localField: 'brand_id',
        foreignField: '_id',
        as: 'brand'
        }
      },
      { $unwind: '$brand' },
      { $match: { 'brand.brand_status': 0 } }, // Chỉ lấy sản phẩm của thương hiệu đang hoạt động
      { $sort: { createdAt: -1 } },
      { $addFields: { main_image: { $arrayElemAt: ['$main_image', 0] } } },
      { $limit: limit },
      // ✅ Project chỉ các trường cần thiết
    {
      $project: {
        name: 1,
        price: 1,
        createdAt: 1,
        views: 1,
        quantity: 1,
        main_image: {
          _id: 1,
          image: 1,
          alt: 1
        },
        brand: {
          _id: 1,
          name: 1
        },
      }
    }
    ]);

    res.json(products);
  } catch (err) {
    res.status(500).json({ error: 'Lỗi lấy sản phẩm', details: err });
  }
});

// http://localhost:3000/api/sp_giam_gia
app.get('/api/sp_giam_gia', async function(req, res) {
const limit = parseInt(req.query.limit, 10) || 10;
try {
  const products = await ProductModel.aggregate([
    {
      $match: { sale_price: { $gt: 0 } }
    },
    {
      $lookup: {
        from: 'product_images',
        let: { productId: '$_id' },
        pipeline: [
          {
            $match: {
              $expr: {
                $and: [
                  { $eq: ['$product_id', '$$productId'] },
                  { $eq: ['$is_main', true] }
                ]
              }
            }
          },
          {
            $project: {
              image: 1,
              alt: 1,
              _id: 1
            }
          }
        ],
        as: 'main_image'
      }
    },
    {$lookup: {
      from: 'brands',
      localField: 'brand_id',
      foreignField: '_id',
      as: 'brand'
      }
    },
    { $unwind: '$brand' },
    { $match: { 'brand.brand_status': 0 } }, // Chỉ lấy sản phẩm của thương hiệu đang hoạt động
    { $addFields: { main_image: { $arrayElemAt: ['$main_image', 0] } } },
      {
        $sort: { sale_price: 1 }
      },
      { $limit: limit },
      // ✅ Project chỉ các trường cần thiết
    {
      $project: {
        name: 1,
        price: 1,
        createdAt: 1,
        views: 1,
        quantity: 1,
        main_image: {
          _id: 1,
          image: 1,
          alt: 1
        },
        brand: {
          _id: 1,
          name: 1
        },
      }
    }
    ]);

    res.json(products);
  } catch (err) {
    res.status(500).json({ error: 'Lỗi lấy sản phẩm giảm giá', details: err });
  }
});

// http://localhost:3000/api/sp_lien_quan/6833ff0acc1ed305e8513aae
app.get('/api/sp_lien_quan/:id', async (req, res) => {
  const limit = parseInt(req.query.limit, 10) || 5;
  const productId = new ObjectId(req.params.id);

  try {
    const product = await ProductModel.findById(productId).lean();
    if (!product) {
      return res.status(404).json({ error: 'Sản phẩm không tồn tại' });
    }

    const brandObjectId = new ObjectId(product.brand_id);

    const relatedProducts = await ProductModel.aggregate([
      {
        $match: {
          brand_id: brandObjectId,
          _id: { $ne: productId }
        }
      },
      {
        $lookup: {
          from: 'product_images',
          let: { pid: '$_id' },
          pipeline: [
            {
              $match: {
                $expr: {
                  $and: [
                    { $eq: ['$product_id', '$$pid'] },
                    { $eq: ['$is_main', true] }
                  ]
                }
              }
            },
            {
              $project: {
                _id: 1,
                image: 1,
                alt: 1
              }
            }
          ],
          as: 'main_image'
        }
      },
      {
        $lookup: {
          from: 'brands',
          localField: 'brand_id',
          foreignField: '_id',
          as: 'brand'
        }
      },
      { $unwind: '$brand' },
      { $match: { 'brand.brand_status': 0 } },
      {
        $addFields: {
          main_image: { $arrayElemAt: ['$main_image', 0] }
        }
      },
      { $limit: limit },
      {
        $project: {
          name: 1,
          price: 1,
          sale_price: 1,
          createdAt: 1,
          views: 1,
          quantity: 1,
          main_image: {
            _id: 1,
            image: 1,
            alt: 1
          },
          brand: {
            _id: 1,
            name: 1
          }
        }
      }
    ]);

    res.json(relatedProducts);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Lỗi lấy sản phẩm liên quan', details: err });
  }
});

// http://localhost:3000/api/brand
app.get('/api/brand', async function (req, res) {
  try {
    const brandsWithProductCount = await BrandModel.aggregate([
      {
        $lookup: {
          from: 'products',
          localField: '_id',
          foreignField: 'brand_id',
          as: 'products'
        }
      },
      {
        $addFields: {
          productCount: { $size: '$products' }
        }
      },
      {
        $project: {
          products: 0
        }
      }
    ]);

    res.json(brandsWithProductCount);
  } catch (err) {
    res.status(500).json({ error: 'Lỗi lấy danh sách thương hiệu', details: err.message });
  }
});

// http://localhost:3000/api/brand/6831eb9c5c1a8be3463e4603
app.get('/api/brand/:id', async function(req, res) { 
    const brandId = new ObjectId(req.params.id);

    try {
      const brand = await BrandModel.findById(brandId, { _id: 1, name: 1, description: 1, image: 1, alt: 1, brand_status: 1 });
      if (!brand) {
        return res.status(404).json({ error: 'Thương hiệu không tồn tại' });
      }
      res.json(brand);
    } catch (err) {
      res.status(500).json({ error: 'Lỗi lấy thương hiệu', details: err });
    }
});

// http://localhost:3000/api/brand/6831eb9c5c1a8be3463e4603/products?limit=10
app.get('/api/brand/:id/products', async function(req, res) {
    const brandId = new ObjectId(req.params.id);
    const limit = parseInt(req.query.limit, 10) || 10;
    
    try {
      const products = await ProductModel.aggregate([
        { $match: { brand_id: new ObjectId(brandId) } },
        {
          $lookup: {
            from: 'product_images',
            let: { productId: '$_id' },
            pipeline: [
              { $match: { $expr: { $and: [
                { $eq: ['$product_id', '$$productId'] },
                { $eq: ['$is_main', true] }
              ] } } },
              { $project: { image: 1, _id: 0 } }
            ],
            as: 'main_image'
          }
        },
        {
          $addFields: {
            main_image: { $arrayElemAt: ['$main_image.image', 0] }
          }
        },
        { $limit: limit }
      ]);
  
      res.json(products);
    }
    catch (err) {
      res.status(500).json({ error: 'Lỗi lấy sản phẩm theo thương hiệu', details: err });
    }
});

// http://localhost:3000/api/products/top-rated?limit=6
app.get('/api/products/top-rated', async function(req, res) {
    const limit = parseInt(req.query.limit) || 6;
    
    try {
      const topRatedProducts = await ProductModel.aggregate([
        {
          $lookup: {
            from: 'order_details',
            localField: '_id',
            foreignField: 'product_id',
            as: 'order_details'
          }
        },
        {
          $lookup: {
            from: 'reviews',
            let: { orderDetailIds: '$order_details._id' },
            pipeline: [
              {
                $match: {
                  $expr: { $in: ['$order_detail_id', '$$orderDetailIds'] }
                }
              }
            ],
            as: 'reviews'
          }
        },
        {
          $addFields: {
            averageRating: {
              $cond: {
                if: { $gt: [{ $size: '$reviews' }, 0] },
                then: { $avg: '$reviews.rating' },
                else: 0
              }
            },
            reviewCount: { $size: '$reviews' }
          }
        },
        {
          $lookup: {
            from: 'product_images',
            let: { productId: '$_id' },
            pipeline: [
              { $match: { $expr: { $and: [
                { $eq: ['$product_id', '$$productId'] },
                { $eq: ['$is_main', true] }
              ] } } },
              { $project: { image: 1, alt: 1, _id: 0 } }
            ],
            as: 'main_image'
          }
        },
        {
          $addFields: {
            main_image: { $arrayElemAt: ['$main_image', 0] }
          }
        },
        {
          $lookup: {
            from: 'brands',
            localField: 'brand_id',
            foreignField: '_id',
            as: 'brand'
          }
        },
        { $unwind: '$brand' },
        {
          $match: {
            'brand.brand_status': 0,
            status: 0,
            quantity: { $gt: 0 }
          }
        },
        {
          $sort: { averageRating: -1, reviewCount: -1 }
        },
        { $limit: limit },
        {
          $project: {
            _id: 1,
            name: 1,
            price: 1,
            sale_price: 1,
            averageRating: { $round: ['$averageRating', 1] },
            reviewCount: 1,
            main_image: 1,
            brand: {
              _id: 1,
              name: 1
            }
          }
        }
      ]);
  
      res.json(topRatedProducts);
    }
    catch (err) {
      res.status(500).json({ error: 'Lỗi lấy sản phẩm được đánh giá cao', details: err });
    }
});

// http://localhost:3000/api/user/6655d0000000000000000002
app.get('/api/user/:userId', async (req, res) => {
    const userId = new ObjectId(req.params.userId);
  
    try {
      const user = await UserModel.findById(userId, {
        _id: 1,
        username: 1,
        email: 1,
        avatar: 1,
        role: 1,
        account_status: 1,
      });
      if (!user) {
        return res.status(404).json({ error: 'Người dùng không tồn tại' });
      }
      res.json(user);
    } catch (err) {
      res.status(500).json({ error: 'Lỗi lấy thông tin người dùng', details: err });
    }
});

// http://localhost:3000/api/product/6833ff0acc1ed305e8513aae
app.get('/api/product/:id', async (req, res) => {
  const { id } = req.params;

  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({ error: 'ID không hợp lệ' });
  }

  const objectId = new ObjectId(id);

  try {
    const product = await ProductModel.aggregate([
      { $match: { _id: objectId } },
      {
        $lookup: {
          from: 'product_images',
          let: { pid: '$_id' },
          pipeline: [
            {
              $match: {
                $expr: { $eq: ['$product_id', '$$pid'] }
              }
            },
            {
              $project: {
                _id: 1,
                image: 1,
                alt: 1,
                is_main: 1
              }
            }
          ],
          as: 'images'
        }
      },
      {
        $addFields: {
          main_image: {
            $arrayElemAt: [
              {
                $map: {
                  input: {
                    $filter: {
                      input: '$images',
                      as: 'img',
                      cond: { $eq: ['$$img.is_main', true] }
                    }
                  },
                  as: 'm',
                  in: { image: '$$m.image', alt: '$$m.alt' },
                }
              },
              0
            ]
          }
        }
      },
      {
        $lookup: {
          from: 'brands',
          localField: 'brand_id',
          foreignField: '_id',
          as: 'brand'
        }
      },
      { $unwind: '$brand' },
      {
        $match: {
          'brand.brand_status': 0
        }
      },
      {
        $project: {
          name: 1,
          description: 1,
          price: 1,
          sale_price: 1,
          quantity: 1,
          views: 1,
          status: 1,
          sex: 1,
          case_diameter: 1,
          style: 1,
          features: 1,
          water_resistance: 1,
          thickness: 1,
          color: 1,
          machine_type: 1,
          strap_material: 1,
          case_material: 1,
          created_at: 1,
          updated_at: 1,
          main_image: 1,
          images: 1,
          brand: {
            _id: 1,
            name: 1
          }
        }
      }
    ]);

    if (product.length === 0) {
      return res.status(404).json({ error: 'Không tìm thấy sản phẩm' });
    }

    // Tăng views
    await ProductModel.updateOne({ _id: objectId }, { $inc: { views: 1 } });

    res.json(product[0]);
  } catch (err) {
    res.status(500).json({ error: 'Lỗi máy chủ', details: err.message });
  }
});

// API lấy danh mục sản phẩm
app.get('/api/category', async (req, res) => {
  try {
    const categories = await CategoryModel.find({});
    res.json(categories);
  } catch (err) {
    res.status(500).json({ error: 'Lỗi lấy danh mục', details: err });
  }
});

// http://localhost:3000/api/sp_filter?category=684bd33394fc9ce76cf76edd&minPrice=1000000sort=price-asc&page=1&limit=12
app.get('/api/sp_filter', async (req, res) => {
  const { category, minPrice, maxPrice, sort, page = 1, limit = 12 } = req.query;
  let filter = {};

  try {
    if (category && category !== 'Tất cả') {
      const categoryObj = await CategoryModel.findOne({ name: category });
      if (categoryObj) {
        const productCategories = await ProductCategoriesModel.find({ category_id: categoryObj._id });
        const productIds = productCategories.map(pc => new mongoose.Types.ObjectId(pc.product_id));
        filter._id = { $in: productIds };
      } else {
        return res.json({ products: [], total: 0, totalPages: 0, currentPage: 1 });
      }
    }

    // Lọc theo giá - sử dụng logic phức tạp hơn để xử lý cả price và sale_price
    if (minPrice || maxPrice) {
      const minPriceNum = minPrice ? Number(minPrice) : 0;
      const maxPriceNum = maxPrice ? Number(maxPrice) : Number.MAX_SAFE_INTEGER;
      
      // Tạo điều kiện phức tạp: sử dụng sale_price nếu có và > 0, ngược lại sử dụng price
      filter.$or = [
        // Trường hợp 1: sale_price > 0 và nằm trong khoảng giá
        {
          $and: [
            { sale_price: { $gt: 0 } },
            { sale_price: { $gte: minPriceNum, $lte: maxPriceNum } }
          ]
        },
        // Trường hợp 2: sale_price = 0 hoặc null, sử dụng price và nằm trong khoảng giá
        {
          $and: [
            { $or: [{ sale_price: 0 }, { sale_price: null }] },
            { price: { $gte: minPriceNum, $lte: maxPriceNum } }
          ]
        }
      ];
    }
    
    let sortOption = {};
    if (sort === 'price-asc') {
      // Sắp xếp theo giá tăng dần: ưu tiên sale_price nếu có, ngược lại dùng price
      sortOption = {
        $addFields: {
          sortPrice: {
            $cond: {
              if: { $gt: ['$sale_price', 0] },
              then: '$sale_price',
              else: '$price'
            }
          }
        }
      };
    } else if (sort === 'price-desc') {
      // Sắp xếp theo giá giảm dần: ưu tiên sale_price nếu có, ngược lại dùng price
      sortOption = {
        $addFields: {
          sortPrice: {
            $cond: {
              if: { $gt: ['$sale_price', 0] },
              then: '$sale_price',
              else: '$price'
            }
          }
        }
      };
    } else {
      sortOption = { _id: 1 };
    }

    const pageNum = Math.max(parseInt(page), 1);
    const limitNum = Math.max(parseInt(limit), 1);
    const skip = (pageNum - 1) * limitNum;

    const total = await ProductModel.countDocuments(filter);
let aggregationPipeline = [
      { $match: filter },
      {
        $lookup: {
          from: 'product_images',
          let: { productId: '$_id' },
          pipeline: [
            { $match: { $expr: { $and: [
              { $eq: ['$product_id', '$$productId'] },
              { $eq: ['$is_main', true] }
            ] } } },
            { $project: { image: 1, _id: 0 } }
          ],
          as: 'mainImage'
        }
      },
      { $addFields: { mainImage: { $arrayElemAt: ['$mainImage.image', 0] } } }
    ];

    // Thêm logic sắp xếp
    if (sort === 'price-asc' || sort === 'price-desc') {
      aggregationPipeline.push({
        $addFields: {
          sortPrice: {
            $cond: {
              if: { $gt: ['$sale_price', 0] },
              then: '$sale_price',
              else: '$price'
            }
          }
        }
      });
      aggregationPipeline.push({ $sort: { sortPrice: sort === 'price-asc' ? 1 : -1 } });
    } else {
      aggregationPipeline.push({ $sort: { _id: 1 } });
    }

    aggregationPipeline.push({ $skip: skip });
    aggregationPipeline.push({ $limit: limitNum });

    const products = await ProductModel.aggregate(aggregationPipeline);
    
    res.json({
      products,
      total,
      totalPages: Math.ceil(total / limitNum),
      currentPage: pageNum
    });
  } catch (err) {
    console.error('Lỗi lọc sản phẩm:', err);
    res.status(500).json({ error: 'Lỗi lọc sản phẩm', details: err });
  }
});


// http://localhost:3000/api/reviews/6833ff0acc1ed305e8513aae
app.get('/api/reviews/:id', async (req, res) => {
  const { id } = req.params;    
  
  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({ error: 'ID không hợp lệ' });
  }

  const objectId = new ObjectId(id);

  const page  = Math.max(parseInt(req.query.page)  || 1, 1);
  const limit = Math.max(parseInt(req.query.limit) || 10, 1);
  const skip  = (page - 1) * limit;

  const pipeline = [
    { $lookup: {                   
        from: 'order_details',
        localField: 'order_detail_id',
        foreignField: '_id',
        as: 'order_details'
    }},
    { $unwind: '$order_details' },
    { $match: { 'order_details.product_id': objectId } }, // so sánh string
    { $lookup: {
        from: 'users',
        localField: 'user_id',
        foreignField: '_id',
        as: 'user'
    }},
    { $unwind: '$user' },
    { $project: {
        rating: 1,
        comment: 1,
        created_at: 1,
        order_detail_id: 1,
        'user._id': 1,
        'user.avatar': 1,
        'user.username': 1,
    }},
    { $sort: { created_at: -1 } },
    { $facet: {
        data:       [ { $skip: skip }, { $limit: limit } ],
        totalCount: [ { $count: 'total' } ]
    }}
  ];

  try {
    const [{ data, totalCount } = { data: [], totalCount: [] }] =
      await ReviewModel.aggregate(pipeline).exec();

    res.json({
      page,
      limit,
      total: totalCount[0]?.total || 0,
      reviews: data
    });
  } catch (err) {
    console.error('Lỗi lấy đánh giá:', err);
    res.status(500).json({ error: 'Lỗi lấy đánh giá', details: err.message });
  }
});

// http://localhost:3000/api/reviews/stats/6833ff0acc1ed305e8513aae
app.get('/api/reviews/stats/:productId', async (req, res) => {
  const { productId } = req.params;

  if (!mongoose.Types.ObjectId.isValid(productId)) {
    return res.status(400).json({ error: 'ID không hợp lệ' });
  }

  const objectId = new mongoose.Types.ObjectId(productId);

  try {
    const stats = await ReviewModel.aggregate([
      {
        $lookup: {
          from: 'order_details',
          localField: 'order_detail_id',
          foreignField: '_id',
          as: 'order_detail',
        },
      },
      { $unwind: '$order_detail' },
      {
        $match: {
          'order_detail.product_id': objectId,
        },
      },
      {
        $group: {
          _id: null,
          totalReviews: { $sum: 1 },
          averageRating: { $avg: '$rating' },
        },
      },
    ]);

    const result = stats[0] || { totalReviews: 0, averageRating: 0 };

    res.json({
      totalReviews: result.totalReviews,
      averageRating: parseFloat(result.averageRating.toFixed(1)),
    });
  } catch (err) {
    res.status(500).json({ error: 'Lỗi thống kê đánh giá', details: err.message });
  }
});

// http://localhost:3000/api/reviews
app.post('/api/reviews', verifyToken , async (req, res) => {
  const { product_id, rating, comment } = req.body;

  if (!req.user || !req.user.userId) {
    return res.status(401).json({ error: 'Bạn cần đăng nhập để bình luận.' });
  }

  const userId = new ObjectId(req.user.userId);
  const productId = new ObjectId(product_id);

  try {
    const purchased = await OrderDetailModel.aggregate([
      { $match: { product_id: productId } },
      {
        $lookup: {
          from: 'orders',
          localField: 'order_id',
          foreignField: '_id',
          as: 'order'
        }
      },
      { $unwind: '$order' },
      { $match: { 'order.user_id': userId } },
      { $limit: 1 }
    ]);

    const purchasedDetail = purchased[0];

    if (!purchasedDetail) {
      return res.status(403).json({ error: 'Bạn chưa mua sản phẩm này.' });
    }

    const existingReview = await ReviewModel.findOne({
      order_detail_id: purchasedDetail._id,
      user_id: userId
    });

    if (existingReview) {
      return res.status(409).json({ error: 'Bạn đã đánh giá sản phẩm này rồi.' });
    }

    const newReview = new ReviewModel({
      order_detail_id: purchasedDetail._id,
      user_id: userId,
      rating,
      comment,
      created_at: new Date(),
    });

    await newReview.save();

    res.status(201).json({ message: 'Đã thêm đánh giá', review: newReview });

  } catch (err) {
    console.error('Lỗi tạo đánh giá:', err);
    res.status(500).json({ error: 'Lỗi tạo đánh giá', details: err.message });
  }
});


app.get('/user/addresses', verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const addresses = await AddressModel.find({ user_id: userId });
    res.json(addresses);
  } catch (error) {
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});


app.post('/user/addresses', verifyToken, async (req, res) => {
  try {
    const { receiver_name, phone, address } = req.body;
    const userId = req.user.userId;

    if (!receiver_name || !phone || !address) {
      return res.status(400).json({ message: 'Vui lòng điền đầy đủ thông tin' });
    }

    const newAddress = new AddressModel({
      user_id: userId,
      receiver_name,
      phone,
      address,
      created_at: new Date(),
      updated_at: new Date()
    });

    const savedAddress = await newAddress.save();
    res.status(201).json(savedAddress);
  } catch (error) {
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

app.put('/user/addresses/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { receiver_name, phone, address } = req.body;
    const userId = req.user.userId;

    const addressToUpdate = await AddressModel.findOne({ _id: id, user_id: userId });
    if (!addressToUpdate) {
      return res.status(404).json({ message: 'Không tìm thấy địa chỉ' });
    }

    addressToUpdate.receiver_name = receiver_name;
    addressToUpdate.phone = phone;
    addressToUpdate.address = address;
    addressToUpdate.updated_at = new Date();

    await addressToUpdate.save();
    res.json(addressToUpdate);
  } catch (error) {
    console.error('Error updating address:', error);
    res.status(500).json({ message: 'Lỗi server' });
  }
});


app.delete('/user/addresses/:id', verifyToken, async (req, res) => {
  try {
    const addressId = req.params.id;
    const userId = req.user.userId;

    // Kiểm tra xem địa chỉ có thuộc về user này không
    const address = await AddressModel.findOne({
      _id: addressId,
      user_id: userId
    });

    if (!address) {
      return res.status(404).json({ 
        message: 'Không tìm thấy địa chỉ hoặc bạn không có quyền xóa' 
      });
    }

    await AddressModel.findByIdAndDelete(addressId);
    res.json({ message: 'Xóa địa chỉ thành công' });
  } catch (error) {
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});


app.get('/api/news', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const news = await NewsModel.aggregate([
      {
        $lookup: {
          from: 'category_news',
          localField: 'categorynews_id',
          foreignField: '_id',
          as: 'category'
        }
      },
      { $unwind: '$category' },
      {
        $project: {
          _id: 1,
          title: 1,
          content: 1,
          image: 1,
          news_status: 1,
          views: 1,
          created_at: 1,
          updated_at: 1,
          'category.name': 1
        }
      },
      { $sort: { created_at: -1 } },
      { $skip: skip },
      { $limit: limit }
    ]);

    const total = await NewsModel.countDocuments();

    res.json({
      news,
      currentPage: page,
      totalPages: Math.ceil(total / limit),
      totalNews: total
    });
  } catch (err) {
    res.status(500).json({ error: 'Lỗi lấy danh sách tin tức', details: err.message });
  }
});

app.get('/api/news/:id', async (req, res) => {
  try {
    const newsId = new ObjectId(req.params.id);
    const news = await NewsModel.aggregate([
      { $match: { _id: newsId } },
      {
        $lookup: {
          from: 'category_news',
          localField: 'categorynews_id',
          foreignField: '_id',
          as: 'category'
        }
      },
      { $unwind: '$category' },
      {
        $project: {
          _id: 1,
          title: 1,
          content: 1,
          image: 1,
          news_status: 1,
          views: 1,
          created_at: 1,
          updated_at: 1,
          'category.name': 1
        }
      }
    ]);

    if (!news.length) {
      return res.status(404).json({ error: 'Không tìm thấy tin tức' });
    }

    res.json(news[0]);
  } catch (err) {
    res.status(500).json({ error: 'Lỗi lấy tin tức', details: err.message });
  }
});

// API tăng lượt xem tin tức
app.post('/api/news/:id/increment-view', async (req, res) => {
  try {
    const newsId = new ObjectId(req.params.id);
    
    // Tăng lượt xem
    const result = await NewsModel.findByIdAndUpdate(
      newsId,
      { $inc: { views: 1 } },
      { new: true }
    );

    if (!result) {
      return res.status(404).json({ error: 'Không tìm thấy tin tức' });
    }

    res.json({ 
      message: 'Đã tăng lượt xem',
      views: result.views 
    });
  } catch (err) {
    res.status(500).json({ error: 'Lỗi tăng lượt xem', details: err.message });
  }
});

app.get('/api/news/category/:categoryId', async (req, res) => {
  try {
    const categoryId = new ObjectId(req.params.categoryId);
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const news = await NewsModel.aggregate([
      { $match: { categorynews_id: categoryId } },
      {
        $lookup: {
          from: 'category_news',
          localField: 'categorynews_id',
          foreignField: '_id',
          as: 'category'
        }
      },
      { $unwind: '$category' },
      {
        $project: {
          _id: 1,
          title: 1,
          content: 1,
          image: 1,
          news_status: 1,
          views: 1,
          created_at: 1,
          updated_at: 1,
          'category.name': 1
        }
      },
      { $sort: { created_at: -1 } },
      { $skip: skip },
      { $limit: limit }
    ]);

    const total = await NewsModel.countDocuments({ categorynews_id: categoryId });

    res.json({
      news,
      currentPage: page,
      totalPages: Math.ceil(total / limit),
      totalNews: total
    });
  } catch (err) {
    res.status(500).json({ error: 'Lỗi lấy tin tức theo danh mục', details: err.message });
  }
});

app.get('/user/wishlist', verifyToken, async (req, res) => {
  try {
      const userId = req.user.userId;
      const wishlistItems = await WishlistModel.find({ user_id: userId })
          .populate('product_id', 'name price main_image description')
          .sort({ created_at: -1 });

      // Lấy main_image nếu thiếu
      const result = await Promise.all(wishlistItems.map(async item => {
          let main_image = item.product_id.main_image;
          if (!main_image) {
              // Nếu chưa có main_image, lấy từ bảng product_images
              const img = await ProductImageModel.findOne({ product_id: item.product_id._id, is_main: true });
              main_image = img ? img.image : '';
          }
          return {
              _id: item._id,
              product_id: item.product_id._id,
              user_id: item.user_id,
              created_at: item.created_at,
              updated_at: item.updated_at,
              product: {
                  _id: item.product_id._id,
                  name: item.product_id.name,
                  price: item.product_id.price,
                  main_image,
                  description: item.product_id.description
              }
          };
      }));

      res.json(result);
  } catch (error) {
      console.error('Error fetching wishlist:', error);
      res.status(500).json({ message: 'Lỗi khi lấy danh sách yêu thích' });
  }
});


app.post('/user/wishlist/:productId', verifyToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const productId = req.params.productId;

        // Check if product exists
        const product = await ProductModel.findById(productId);
        if (!product) {
            return res.status(404).json({ message: 'Không tìm thấy sản phẩm' });
        }

        // Check if product is already in wishlist
        const existingWishlistItem = await WishlistModel.findOne({
            user_id: userId,
            product_id: productId
        });

        if (existingWishlistItem) {
            return res.status(400).json({ message: 'Sản phẩm đã có trong danh sách yêu thích' });
        }

        // Create new wishlist item
        const wishlistItem = new WishlistModel({
            user_id: userId,
            product_id: productId
        });

        await wishlistItem.save();
        res.status(201).json({ message: 'Đã thêm vào danh sách yêu thích' });
    } catch (error) {
        console.error('Error adding to wishlist:', error);
        res.status(500).json({ message: 'Lỗi khi thêm vào danh sách yêu thích' });
    }
});


app.delete('/user/wishlist/:productId', verifyToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const productId = req.params.productId;

        // Find and delete the wishlist item
        const result = await WishlistModel.findOneAndDelete({
            user_id: userId,
            product_id: productId
        });

        if (!result) {
            return res.status(404).json({ message: 'Không tìm thấy sản phẩm trong danh sách yêu thích' });
        }

        res.json({ message: 'Đã xóa khỏi danh sách yêu thích' });
    } catch (error) {
        console.error('Error removing from wishlist:', error);
        res.status(500).json({ message: 'Lỗi khi xóa khỏi danh sách yêu thích' });
    }
});

// http://localhost:3000/api/check
app.post('/api/check', async (req, res) => {
  const { voucher_code, user_id, order_total } = req.body;

  if (!voucher_code || !order_total) {
    return res.status(400).json({ message: "Thiếu thông tin yêu cầu" });
  }

  try {
    const voucher = await VoucherModel.findOne({ voucher_code: voucher_code.trim() });

    if (!voucher) {
      return res.status(404).json({ message: "Mã voucher không tồn tại" });
    }

    const now = new Date();
    if (voucher.start_date > now || voucher.end_date < now) {
      return res.status(400).json({ message: "Voucher đã hết hạn hoặc chưa có hiệu lực" });
    }

    // Kiểm tra đã dùng chưa nếu có user_id
    if (user_id) {
      const existedOrder = await OrderModel.findOne({
        user_id: new mongoose.Types.ObjectId(user_id),
        voucher_id: voucher._id,
        order_status: { $ne: "cancelled" },
      });

      if (existedOrder) {
        return res.status(400).json({ message: "Bạn đã sử dụng voucher này rồi" });
      }
    }

    if (order_total < voucher.minimum_order_value) {
      return res.status(400).json({
        message: `Đơn hàng phải đạt tối thiểu ${voucher.minimum_order_value.toLocaleString()}₫ để áp dụng voucher này.`,
      });
    }

    let discountAmount = 0;
    if (voucher.discount_type === "percentage") {
      discountAmount = (order_total * voucher.discount_value) / 100;
    } else if (voucher.discount_type === "fixed") {
      discountAmount = voucher.discount_value;
    }

    if (voucher.max_discount && discountAmount > voucher.max_discount) {
      discountAmount = voucher.max_discount;
    }

    return res.status(200).json({
      message: "Voucher hợp lệ",
      data: {
        voucher_id: voucher._id,
        discount_amount: discountAmount,
        discount_type: voucher.discount_type,
        discount_value: voucher.discount_value,
      },
    });
  } catch (err) {
    console.error("Lỗi kiểm tra voucher:", err);
    return res.status(500).json({ message: "Lỗi server" });
  }
});

// http://localhost:3000/api/checkout
app.post("/api/checkout", async (req, res) => {
  try {
    const {
      cart,
      user_id,
      address_id,
      new_address,
      payment_method_id,
      voucher_id,
      discount_amount,
      note,
      total_amount
    } = req.body;

    if (!cart || cart.length === 0) {
      return res.status(400).json({ message: "Giỏ hàng không được để trống." });
    }

    if (!payment_method_id || !total_amount) {
      return res.status(400).json({ message: "Thiếu phương thức thanh toán hoặc tổng tiền." });
    }

    let finalAddressId = address_id;

    // Nếu không có address_id mà có new_address → tạo mới
    if (!address_id && new_address) {
      const newAddr = await AddressModel.create({
        ...new_address,
        user_id: user_id || null,
        created_at: new Date(),
        updated_at: new Date()
      });
      finalAddressId = newAddr._id;
    }

    // Tạo đơn hàng
    const newOrder = await OrderModel.create({
      user_id: user_id || null,
      voucher_id: voucher_id || null,
      address_id: finalAddressId,
      payment_method_id: payment_method_id,
      shipping_fee: 0,
      note: note || "",
      total_amount: total_amount,
      discount_amount: discount_amount || 0,
      order_status: "pending",
      created_at: new Date(),
      updated_at: new Date()
    });

    // Thêm các sản phẩm trong đơn hàng (giả sử có bảng order_items)
    const orderItems = cart.map((item) => ({
      order_id: newOrder._id,
      product_id: item._id,
      quantity: item.so_luong,
      price: item.sale_price > 0 ? item.sale_price : item.price
    }));

    await OrderDetailModel.insertMany(orderItems);

    return res.status(200).json({ message: "Đặt hàng thành công", order_id: newOrder._id });
  } catch (err) {
    console.error("Lỗi khi tạo đơn hàng:", err);
    return res.status(500).json({ message: "Lỗi server" });
  }
});

// http://localhost:3000/api/payment-method
app.get("/api/payment-method", async function (req, res) {
  try {
    const filter = { is_active: true };
    const list = await PaymentMethodModel.find(filter)
      .sort({ _id: -1 })

    res.json({ list });
  } catch (error) {
    console.error("Lỗi khi lấy danh sách phương thức thanh toán:", error);
    res
      .status(500)
      .json({ error: "Lỗi khi lấy danh sách phương thức thanh toán." });
  }
});

// http://localhost:3000/api/orders?user_id=6852bc7cdbb9b28715884c6f
app.get("/api/orders", async (req, res) => {
  const { user_id } = req.query;

  if (!user_id) {
    return res.status(400).json({ message: "Thiếu user_id" });
  }

  try {
    const orders = await OrderModel.find({ user_id })
      .populate("payment_method_id", "name") // lấy trường name của payment method
      .populate("address_id") // nếu cần thêm address
      .populate("voucher_id") // nếu cần thêm thông tin voucher
      .sort({ created_at: -1 });

    res.json(orders);
  } catch (err) {
    console.error("Lỗi khi lấy đơn hàng theo user_id:", err);
    res.status(500).json({ success: false, message: "Lỗi server" });
  }
});

// http://localhost:3000/api/order-details/6833ff0acc1ed305e8513ab1
app.get("/api/order-details/:order_id", async (req, res) => {
  const {order_id} = req.params;
  
    try {
      const chiTietDonHangs = await OrderDetailModel.find({ order_id }).populate({
        path: "product_id",
        model: "products",
        select: "name price sale_price status",
      });
  
      const populated = await Promise.all(
        chiTietDonHangs.map(async (item) => {
          const productId = item?.product_id?._id;
          let main_image = null;
  
          if (productId) {
            main_image = await ProductImageModel.findOne({
              product_id: productId,
              is_main: true,
            }).select("image alt");
          }
  
          return {
            ...item.toObject(),
            product_id: {
              ...item.product_id?.toObject?.(),
              main_image,
            },
          };
        })
      );
  
      if (populated.length > 0) {
        res.json(populated);
      } else {
        res
          .status(404)
          .json({ error: "Không tìm thấy chi tiết cho đơn hàng này." });
      }
    } catch (error) {
      console.error("Lỗi lấy chi tiết đơn hàng:", error);
      res.status(500).json({ error: "Lỗi khi lấy chi tiết đơn hàng." });
    }
});

// http://localhost:3000/api/cancel-order/685b4e8f29e55eefd9a43262
app.put("/api/cancel-order/:order_id", async (req, res) => {
  try {
    const order_id = new ObjectId(req.params.order_id);
    
    const order = await OrderModel.findById(order_id);

    if (!order) {
      return res.status(404).json({ message: "Không tìm thấy đơn hàng." });
    }

    if (order.order_status === "cancelled") {
      return res.status(400).json({ message: "Đơn hàng đã được hủy." });
    }

    // Chỉ cho hủy nếu trạng thái là "pending" hoặc "processing"
    if (order.order_status !== "pending" && order.order_status !== "processing") {
      return res.status(400).json({
        message: `Không thể hủy đơn hàng khi đang ở trạng thái: ${order.order_status}.`
      });
    }

    // Cập nhật trạng thái đơn hàng
    order.order_status = "cancelled";
    order.updated_at = new Date();
    await order.save();

    res.json({ message: "Đơn hàng đã được hủy thành công." });
  } catch (error) {
    console.error("Lỗi khi hủy đơn hàng:", error);
    res.status(500).json({ message: "Lỗi khi hủy đơn hàng." });
  }
});



// http://localhost:3000/api/reviews/user/6852bc7cdbb9b28715884c6f
app.get("/reviews/user", verifyToken, async (req, res) => {
  const userId = req.user.userId;

  if (!mongoose.Types.ObjectId.isValid(userId)) {
    return res.status(400).json({ error: "ID người dùng không hợp lệ" });
  }

  try {
    const reviews = await ReviewModel.find(
      { user_id: userId },
      { order_detail_id: 1, rating: 1, _id: 0 }
    );

    res.json(reviews);
  } catch (err) {
    console.error("Lỗi khi lấy đánh giá:", err);
    res.status(500).json({ error: "Không thể lấy danh sách đánh giá" });
  }
});



// ! <== Admin ==>
// ! <== Category ==>
  app.get("/api/admin/categoryProduct", async function (req, res) {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 1000000;
    const skip = (page - 1) * limit;
  
    try {
      const total = await CategoryModel.countDocuments();
      const list = await CategoryModel.find()
        .sort({ _id: -1 })
        .skip(skip)
        .limit(limit);
  
      res.json({ list, total });
    } catch (error) {
      console.error("Lỗi khi truy vấn cơ sở dữ liệu:", error);
      res.status(500).json({ error: "Lỗi khi lấy danh sách loại sản phẩm." });
    }
  });
  
  app.get("/api/admin/categoryProduct/:id", async (req, res) => {
    const categoryProductId = req.params.id;
  
    try {
      const categoryPro = await CategoryModel.findById(categoryProductId);
  
      if (!categoryPro) {
        return res.status(404).json({ error: "Không tìm thấy loại sản phẩm." });
      }
  
      res.json({ categoryPro });
    } catch (error) {
      console.error(
        "Lỗi khi truy vấn loại sản phẩm theo ID:",
        error.message || error
      );
      res.status(500).json({ error: "Lỗi khi lấy loại sản phẩm." });
    }
  });
  
  app.post(
    "/api/admin/categoryProduct/them",
    uploadCateProduct.single("image"),
    async function (req, res) {
      const { name, alt, category_status } = req.body;
      const image = req.file ? `${req.file.filename}` : null;
  
      try {
        const newLoai = new CategoryModel({
          name,
          image,
          alt,
          category_status:
            category_status === undefined ? 0 : parseInt(category_status),
          created_at: new Date(),
          updated_at: new Date(),
        });
  
        await newLoai.save();
        res.status(200).json({ message: "Thêm loại sản phẩm thành công!" });
      } catch (error) {
        console.error("Lỗi khi thêm loại sản phẩm:", error);
        res.status(500).json({ error: "Lỗi khi thêm loại sản phẩm." });
      }
    }
  );
  
  app.put(
    "/api/admin/categoryProduct/sua/:id",
    uploadCateProduct.single("image"),
    async function (req, res) {
      const id = req.params.id;
      const { name, alt, category_status } = req.body;
      const image = req.file ? `${req.file.filename}` : req.body.image_cu;
  
      try {
        const updatedLoai = await CategoryModel.findByIdAndUpdate(
          id,
          {
            name,
            image,
            alt,
            category_status:
              category_status === undefined ? 0 : parseInt(category_status),
            updated_at: new Date(),
          },
          { new: true }
        );
  
        if (!mongoose.Types.ObjectId.isValid(id)) {
          return res.status(400).json({ error: "ID không hợp lệ." });
        }
  
        if (updatedLoai) {
          res.json({
            message: "Cập nhật loại sản phẩm thành công!",
            loai: updatedLoai,
          });
        } else {
          res.status(404).json({ error: "Không tìm thấy loại sản phẩm." });
        }
      } catch (error) {
        console.error("Chi tiết lỗi cập nhật:", error.message || error);
        res.status(500).json({ error: "Lỗi khi cập nhật loại sản phẩm." });
      }
    }
  );
  
  app.delete("/api/admin/categoryProduct/xoa/:id", async function (req, res) {
    const id = req.params.id;
  
    try {
      const count = await ProductCategoriesModel.countDocuments({
        category_id: id,
      });
      if (count > 0) {
        return res.status(400).json({
          thong_bao: "Không thể xóa vì vẫn còn sản phẩm thuộc loại này.",
        });
      }
  
      const result = await CategoryModel.findByIdAndDelete(id);
      if (result) {
        res.json({ message: "Xóa loại sản phẩm thành công!" });
      } else {
        res.status(404).json({ error: "Không tìm thấy loại sản phẩm." });
      }
    } catch (error) {
      console.error("Lỗi khi xóa loại sản phẩm:", error);
      res.status(500).json({ error: "Lỗi khi xóa loại sản phẩm." });
    }
  });
  // ! <== End Category ==>
  
  // ! <== Product ==>
    // Lấy danh sách sản phẩm
  // http://localhost:3000/api/admin/product?page=1&limit=10
  app.get("/api/admin/product", async function (req, res) {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
  
    try {
      const total = await ProductModel.countDocuments();
      const products = await ProductModel.find()
        .populate({
          path: "brand_id",
          model: "brands",
          select: "name",
        })
        .sort({ created_at: -1 })
        .skip(skip)
        .limit(limit);
  
      const list = await Promise.all(
        products.map(async (product) => {
          const main_image = await ProductImageModel.findOne({
            product_id: product._id,
            is_main: true,
          }).select("image alt");
  
          const categoryMap = await ProductCategoriesModel.find({
            product_id: product._id,
          }).populate({
            path: "category_id",
            model: "categories",
            select: "name",
          });
  
          const categories = categoryMap.map((item) => item.category_id);
  
          const sold = await OrderDetailModel.aggregate([
            { $match: { product_id: product._id } },
            { $group: { _id: "$product_id", total: { $sum: "$quantity" } } },
          ]);
  
          const sold_count = sold[0]?.total || 0;
  
          return {
            ...product.toObject(),
            main_image,
            categories,
            sold: sold_count,
          };
        })
      );
  
      res.json({ list, total });
    } catch (error) {
      console.error("Lỗi khi truy vấn MongoDB:", error);
      res.status(500).json({ error: "Lỗi khi lấy danh sách sản phẩm." });
    }
  });
  
  // http://localhost:3000/api/admin/product/
  app.get("/api/admin/product/:id", async (req, res) => {
    const productId = req.params.id;
  
    try {
      const product = await ProductModel.findById(productId).populate({
        path: "brand_id",
        model: "brands",
        select: "name",
      });
  
      if (!product) {
        return res.status(404).json({ error: "Không tìm thấy sản phẩm." });
      }
  
      const images = await ProductImageModel.find({
        product_id: productId,
      }).select("image alt is_main");
  
      const categoryMap = await ProductCategoriesModel.find({
        product_id: productId,
      }).populate({
        path: "category_id",
        model: "categories",
        select: "name",
      });
  
      const categories = categoryMap.map((item) => item.category_id);
  
      // Số lượng đã bán
      const sold = await OrderDetailModel.aggregate([
        { $match: { product_id: product._id } },
        { $group: { _id: "$product_id", total: { $sum: "$quantity" } } },
      ]);
  
      const sold_count = sold[0]?.total || 0;
  
      res.json({
        ...product.toObject(),
        images,
        categories,
        sold: sold_count,
      });
    } catch (error) {
      console.error("Lỗi khi lấy chi tiết sản phẩm:", error);
      res.status(500).json({ error: "Không thể lấy chi tiết sản phẩm." });
    }
  });
  
  app.post(
    "/api/admin/product/them",
    upload.fields([
      { name: "main_image", maxCount: 1 },
      { name: "sub_images", maxCount: 10 },
    ]),
    async (req, res) => {
      try {
        const {
          brand_id,
          name,
          description,
          price,
          sale_price,
          status,
          quantity,
          sex,
          case_diameter,
          style,
          features,
          water_resistance,
          thickness,
          color,
          machine_type,
          strap_material,
          case_material,
          category_ids,
        } = req.body;
  
        const newProduct = await ProductModel.create({
          brand_id,
          name,
          description,
          price,
          sale_price,
          status,
          quantity,
          sex,
          case_diameter,
          style,
          features,
          water_resistance,
          thickness,
          color,
          machine_type,
          strap_material,
          case_material,
          created_at: new Date(),
          updated_at: new Date(),
        });
  
        const productId = newProduct._id;
  
        // Ảnh chính
        if (req.files["main_image"]?.length) {
          const main = req.files["main_image"][0];
          await ProductImageModel.create({
            product_id: productId,
            image: main.filename,
            is_main: true,
            created_at: new Date(),
            updated_at: new Date(),
          });
        }
  
        // Ảnh phụ
        if (req.files["sub_images"]?.length) {
          const subImgs = req.files["sub_images"];
          const subDocs = subImgs.map((img) => ({
            product_id: productId,
            image: img.filename,
            is_main: false,
            created_at: new Date(),
            updated_at: new Date(),
          }));
          await ProductImageModel.insertMany(subDocs);
        }
  
        // Danh mục
        const categories = category_ids?.split(",") || [];
        await Promise.all(
          categories.map((categoryId) =>
            ProductCategoriesModel.create({
              product_id: productId,
              category_id: categoryId,
            })
          )
        );
  
        res.status(200).json({ message: "Thêm sản phẩm thành công!" });
      } catch (error) {
        console.error("Lỗi khi thêm sản phẩm:", error);
        res.status(500).json({ error: "Lỗi khi thêm sản phẩm." });
      }
    }
  );
  
  app.put(
    "/api/admin/product/sua/:id",
    upload.fields([
      { name: "main_image", maxCount: 1 },
      { name: "sub_images", maxCount: 10 },
    ]),
    async (req, res) => {
      const productId = req.params.id;
  
      try {
        const {
          brand_id,
          name,
          description,
          price,
          sale_price,
          status,
          quantity,
          sex,
          case_diameter,
          style,
          features,
          water_resistance,
          thickness,
          color,
          machine_type,
          strap_material,
          case_material,
          category_ids,
        } = req.body;
  
        const updatedProduct = await ProductModel.findByIdAndUpdate(
          productId,
          {
            brand_id,
            name,
            description,
            price,
            sale_price,
            status,
            quantity,
            sex,
            case_diameter,
            style,
            features,
            water_resistance,
            thickness,
            color,
            machine_type,
            strap_material,
            case_material,
            updated_at: new Date(),
          },
          { new: true }
        );
  
        if (!updatedProduct) {
          return res.status(404).json({ error: "Không tìm thấy sản phẩm." });
        }
  
        if (req.files["main_image"]?.length) {
          await ProductImageModel.deleteMany({
            product_id: productId,
            is_main: true,
          });
  
          const mainImg = req.files["main_image"][0];
          await ProductImageModel.create({
            product_id: productId,
            image: mainImg.filename,
            is_main: true,
            created_at: new Date(),
            updated_at: new Date(),
          });
        }
  
        if (req.files["sub_images"]?.length) {
          await ProductImageModel.deleteMany({
            product_id: productId,
            is_main: false,
          });
  
          const subImgs = req.files["sub_images"];
          const subDocs = subImgs.map((img) => ({
            product_id: productId,
            image: img.filename,
            is_main: false,
            created_at: new Date(),
            updated_at: new Date(),
          }));
          await ProductImageModel.insertMany(subDocs);
        }
  
        const categories = category_ids?.split(",") || [];
        await ProductCategoriesModel.deleteMany({ product_id: productId });
  
        await Promise.all(
          categories.map((categoryId) =>
            ProductCategoriesModel.create({
              product_id: productId,
              category_id: categoryId,
            })
          )
        );
  
        res.json({
          message: "Cập nhật sản phẩm thành công!",
          product: updatedProduct,
        });
      } catch (error) {
        console.error("Lỗi khi cập nhật sản phẩm:", error);
        res.status(500).json({ error: "Lỗi khi cập nhật sản phẩm." });
      }
    }
  );
  
  app.delete("/api/admin/product/xoa/:id", async (req, res) => {
    const id = req.params.id;
  
    try {
      const deleted = await ProductModel.findByIdAndDelete(id);
  
      if (!deleted) {
        return res
          .status(404)
          .json({ error: "Không tìm thấy sản phẩm với ID này." });
      }
  
      await ProductImageModel.deleteMany({ product_id: id });
      await ProductCategoriesModel.deleteMany({ product_id: id });
  
      res.json({ message: "Xóa sản phẩm thành công!" });
    } catch (error) {
      console.error("Lỗi khi xóa sản phẩm:", error);
      res.status(500).json({ error: "Lỗi khi xóa sản phẩm." });
    }
  });
  // ! <== End Products ==>
  
  // ! <== User ==>
  // * Role chắc để user = 0, admin = 1, admin cấp cao = 2. Status thì 0 bth, 1 khóa.
  // API lấy thông tin role mapping
  app.get("/api/admin/roles", async (req, res) => {
    const roles = {
      "0": "Người dùng",
      "1": "Admin",
      "2": "Super Admin"
    };
    res.json(roles);
  });

  app.get("/api/admin/user", async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
  
    try {
      const total = await UserModel.countDocuments();
      const list = await UserModel.find()
        .skip(skip)
        .limit(limit)
        .sort({ created_at: -1 })
        .populate("addresses"); // Populate field từ virtual

      // Thêm thông tin role text cho mỗi user
      const listWithRoleText = list.map(user => {
        const userObj = user.toObject();
        const roleText = {
          "0": "Người dùng",
          "1": "Admin", 
          "2": "Super Admin"
        }[userObj.role] || "Không xác định";
        
        return {
          ...userObj,
          roleText
        };
      });
  
      res.json({ list: listWithRoleText, total });
    } catch (error) {
      console.error("Lỗi khi truy vấn MongoDB:", error);
      res.status(500).json({ error: "Lỗi khi lấy danh sách người dùng." });
    }
  });
  
  app.get("/api/admin/user/:id", async (req, res) => {
    const { id } = req.params;
  
    try {
      const user = await UserModel.findById(id).populate("addresses");
  
      if (!user) {
        return res.status(404).json({ error: "Không tìm thấy người dùng." });
      }
  
      res.json(user);
    } catch (error) {
      console.error("Lỗi khi truy vấn MongoDB:", error);
      res.status(500).json({ error: "Lỗi khi lấy người dùng theo ID." });
    }
  });
  
  // * Đăg nhập để test API không phải chính thức, chính thức sài bên client
  app.post("/api/login", async (req, res) => {
    const { username, password } = req.body;
  
    const user = await UserModel.findOne({ username });
    if (!user) return res.status(401).json({ message: "Sai tài khoản" });
  
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ message: "Sai mật khẩu" });
    }
  
    const token = jwt.sign(
      {
        _id: user._id,
        username: user.username,
        role: user.role,
      },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );
  
    res.json({ message: "Đăng nhập thành công", token });
  });
  
  // * Chỉ Super Admin mới tạo được Admin, không cho tạo Super Admin
  app.post("/api/admin/user/them", verifyToken, isSuperAdmin, async (req, res) => {
    try {
      const currentUser = req.user;
      console.log(currentUser);
  
      const { username, password, email, role } = req.body;
  
      if (!username || !password || !email) {
        return res
          .status(400)
          .json({ message: "Vui lòng cung cấp đầy đủ thông tin." });
      }
  
      if (role >= currentUser.role) {
        return res.status(403).json({
          message: "Không thể tạo tài khoản với quyền ngang hoặc cao hơn bạn.",
        });
      }
  
      const existingUser = await UserModel.findOne({
        $or: [{ username }, { email }],
      });
  
      if (existingUser) {
        return res
          .status(400)
          .json({ message: "Username hoặc email đã tồn tại" });
      }
  
      const hashedPassword = await bcrypt.hash(password, 10);
  
      const newUser = new UserModel({
        username,
        password_hash: hashedPassword,
        email,
        role: role || 1,
        account_status: 0,
      });
  
      await newUser.save();
      const { password_hash, ...userSafe } = newUser.toObject();
  
      res
        .status(201)
        .json({ message: "Tạo người dùng thành công", user: userSafe });
    } catch (error) {
      console.error("Lỗi khi thêm người dùng:", error);
      res.status(500).json({ message: "Lỗi server", error: error.message });
    }
  });
  
  // * Đặt lại mật khẩu - chỉ Super Admin
  app.post("/api/admin/user/doiMk/:id", verifyToken, isSuperAdmin, async (req, res) => {
    const { id } = req.params;
    const { newPassword } = req.body;
    const currentUser = req.user;
  
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ message: "ID không hợp lệ" });
    }
  
    try {
      const targetUser = await UserModel.findById(id);
      if (!targetUser) {
        return res.status(404).json({ message: "Không tìm thấy người dùng" });
      }
  
      if (targetUser._id.equals(currentUser._id)) {
        return res
          .status(400)
          .json({ message: "Không thể tự reset mật khẩu của chính mình" });
      }
  
      const hashed = await bcrypt.hash(newPassword, 10);
      await UserModel.findByIdAndUpdate(id, {
        password_hash: hashed,
        updated_at: new Date(),
      });
  
      res.json({ message: "Đặt lại mật khẩu thành công" });
    } catch (error) {
      console.error("Lỗi khi đặt lại mật khẩu:", error);
      res.status(500).json({ message: "Lỗi server" });
    }
  });
  
  app.put("/api/admin/user/sua/:id", verifyToken, async (req, res) => {
    const { id } = req.params;
    const { username, role, account_status } = req.body;
    const currentUser = req.user;
  
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: "ID không hợp lệ" });
    }
  
    try {
      const targetUser = await UserModel.findById(id);
      if (!targetUser) {
        return res.status(404).json({ error: "Không tìm thấy người dùng." });
      }
  
      if (Number(currentUser.role) !== 2) {
        if (targetUser.role >= currentUser.role) {
          return res
            .status(403)
            .json({ message: "Không có quyền chỉnh sửa người dùng này." });
        }
  
        if (role && role !== targetUser.role) {
          return res
            .status(403)
            .json({ message: "Bạn không có quyền thay đổi vai trò." });
        }
  
        if (typeof account_status !== "undefined" && targetUser.role === 2) {
          return res.status(403).json({
            message: "Bạn không được sửa trạng thái của admin cấp cao.",
          });
        }
      }
  
      const updatedUser = await UserModel.findByIdAndUpdate(
        id,
        {
          username,
          role: currentUser.role === 2 ? role : targetUser.role,
          account_status,
          updated_at: new Date(),
        },
        { new: true }
      ).select("-password_hash");
  
      res.json({
        message: "Cập nhật người dùng thành công",
        user: updatedUser,
      });
    } catch (error) {
      console.error("Lỗi khi cập nhật người dùng:", error);
      res.status(500).json({ error: "Lỗi server" });
    }
  });
  
  app.delete("/api/admin/user/xoa/:id", verifyToken, canDeleteUser, async (req, res) => {
    const { id } = req.params;
    const currentUser = req.user;
  
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: "ID không hợp lệ" });
    }
  
    try {
      const targetUser = await UserModel.findById(id);
  
      if (!targetUser) {
        return res.status(404).json({ error: "Không tìm thấy người dùng." });
      }
  
      // Không thể tự xóa chính mình
      if (targetUser._id.equals(currentUser._id)) {
        return res.status(400).json({ message: "Không thể tự xóa chính mình." });
      }
  
      // Super admin không thể xóa super admin khác
      if (targetUser.role === "2" && currentUser.role === "2") {
        return res.status(403).json({ message: "Super Admin không thể xóa Super Admin khác." });
      }
  
      await UserModel.findByIdAndDelete(id);
      res.json({ message: "Xóa người dùng thành công" });
    } catch (error) {
      console.error("Lỗi khi xóa người dùng:", error);
      res.status(500).json({ error: "Lỗi server khi xóa người dùng." });
    }
  });
  
  // ! <== End User ==>
  
  // ! <== Order ==>
  app.get("/api/admin/order", async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
  
    try {
      const total = await OrderModel.countDocuments();
  
      const list = await OrderModel.find()
        .sort({ created_at: -1 })
        .skip(skip)
        .limit(limit)
        .populate({
          path: "user_id",
          model: "users",
          select: "username email",
          populate: {
            path: "addresses",
            model: "address",
            select: "receiver_name phone address",
          },
        })
        .populate({
          path: "voucher_id",
          model: "vouchers",
          select: "voucher_name voucher_code discount_type discount_value",
        })
        .populate({
          path: "payment_method_id",
          model: "payment_methods",
          select: "name",
        });
  
      res.json({ list, total });
    } catch (error) {
      console.error("Lỗi khi truy vấn đơn hàng:", error);
      res.status(500).json({ error: "Lỗi khi lấy danh sách đơn hàng." });
    }
  });
  
  app.get("/api/admin/order/chitiet/:id_dh", async (req, res) => {
    const order_id = req.params.id_dh;
  
    try {
      const chiTietDonHangs = await OrderDetailModel.find({ order_id }).populate({
        path: "product_id",
        model: "products",
        select: "name price sale_price status",
      });
  
      const populated = await Promise.all(
        chiTietDonHangs.map(async (item) => {
          const productId = item?.product_id?._id;
          let main_image = null;
  
          if (productId) {
            main_image = await ProductImageModel.findOne({
              product_id: productId,
              is_main: true,
            }).select("image alt");
          }
  
          return {
            ...item.toObject(),
            product_id: {
              ...item.product_id?.toObject?.(),
              main_image,
            },
          };
        })
      );
  
      if (populated.length > 0) {
        res.json(populated);
      } else {
        res
          .status(404)
          .json({ error: "Không tìm thấy chi tiết cho đơn hàng này." });
      }
    } catch (error) {
      console.error("Lỗi lấy chi tiết đơn hàng:", error);
      res.status(500).json({ error: "Lỗi khi lấy chi tiết đơn hàng." });
    }
  });
  
  app.put("/api/admin/order/suaStatus/:id", async (req, res) => {
    const id = req.params.id;
    const { order_status } = req.body;
  
    try {
      const updated = await OrderModel.findByIdAndUpdate(
        id,
        { order_status, updated_at: new Date() },
        { new: true }
      );
  
      if (updated) {
        res.json({
          message: "Cập nhật trạng thái đơn hàng thành công!",
          order: updated,
        });
      } else {
        res.status(404).json({ error: "Không tìm thấy đơn hàng với ID này." });
      }
    } catch (error) {
      console.error("Lỗi cập nhật trạng thái đơn hàng:", error);
      res.status(500).json({ error: "Lỗi khi cập nhật trạng thái đơn hàng." });
    }
  });
  // ! <== End Order ==>
  
  // ! <== News ==>
  app.get("/api/admin/news", async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
  
    try {
      const total = await NewsModel.countDocuments();
      const list = await NewsModel.find()
        .populate({
          path: "categorynews_id",
          model: "category_news",
          select: "name",
        })
        .sort({ _id: -1 })
        .skip(skip)
        .limit(limit);
  
      res.json({ list, total });
    } catch (error) {
      console.error("Lỗi khi truy vấn tin tức:", error);
      res.status(500).json({ error: "Lỗi khi lấy danh sách tin tức." });
    }
  });
  
  app.get("/api/admin/news/:id", async (req, res) => {
    const newsId = req.params.id;
  
    try {
      const news = await NewsModel.findById(newsId);
  
      if (!news) {
        return res.status(404).json({ error: "Không tìm thấy loại sản phẩm." });
      }
  
      res.json({ news });
    } catch (error) {
      console.error(
        "Lỗi khi truy vấn loại sản phẩm theo ID:",
        error.message || error
      );
      res.status(500).json({ error: "Lỗi khi lấy loại sản phẩm." });
    }
  });
  
  app.post(
    "/api/admin/news/them",
    uploadNew.single("image"),
    async (req, res) => {
      try {
        const { title, content, categorynews_id, news_status } = req.body;
  
        const image = req.file ? req.file.filename : null;
  
        const newTin = await NewsModel.create({
          title,
          content,
          categorynews_id,
          news_status: news_status == undefined ? 0 : parseInt(news_status),
          image,
          created_at: new Date(),
          updated_at: new Date(),
        });
  
        res.status(201).json({
          message: "Thêm tin tức thành công!",
          tin_tuc: newTin,
        });
      } catch (error) {
        console.error("Lỗi khi thêm tin tức:", error);
        res.status(500).json({
          error: "Lỗi khi thêm tin tức",
          details: error.message,
        });
      }
    }
  );
  
  app.put(
    "/api/admin/news/sua/:id",
    uploadNew.single("image"),
    async (req, res) => {
      const id = req.params.id;
      const { title, content, categorynews_id, news_status } = req.body;
  
      const image = req.file ? req.file.filename : null;
  
      try {
        const updateData = {
          title,
          content,
          categorynews_id,
          news_status: news_status == undefined ? 0 : parseInt(news_status),
          updated_at: new Date(),
        };
  
        if (image) updateData.image = image;
  
        const updatedTin = await NewsModel.findByIdAndUpdate(id, updateData, {
          new: true,
        });
  
        if (updatedTin) {
          res.json({
            message: "Cập nhật tin tức thành công!",
            tin_tuc: updatedTin,
          });
        } else {
          res.status(404).json({ error: "Không tìm thấy tin tức với ID này." });
        }
      } catch (error) {
        console.error("Lỗi khi cập nhật tin tức:", error);
        res.status(500).json({
          error: "Lỗi khi cập nhật tin tức",
          details: error.message,
        });
      }
    }
  );
  
  app.delete("/api/admin/news/xoa/:id", async (req, res) => {
    const id = req.params.id;
  
    try {
      const deleted = await NewsModel.findByIdAndDelete(id);
  
      if (deleted) {
        res.json({ message: "Xóa thành công!" });
      } else {
        res.status(404).json({ error: "Không tìm thấy tin tức với ID này." });
      }
    } catch (error) {
      console.error("Lỗi khi xóa tin tức:", error);
      res.status(500).json({ error: "Lỗi khi xóa tin tức." });
    }
  });
  // ! <== End News ==>
  
  // ! <== Category News ==>
  app.get("/api/admin/categoryNews", async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
  
    try {
      const total = await CategoryNewsModel.countDocuments();
      const list = await CategoryNewsModel.find()
        .sort({ _id: -1 })
        .skip(skip)
        .limit(limit);
  
      res.json({ list, total });
    } catch (error) {
      console.error("Lỗi khi truy vấn:", error);
      res.status(500).json({ error: "Lỗi khi lấy danh sách loại tin." });
    }
  });
  
  app.get("/api/admin/categoryNews/:id", async (req, res) => {
    const categoryNewsId = req.params.id;
  
    try {
      const categoryNews = await CategoryNewsModel.findById(categoryNewsId);
  
      if (!categoryNews) {
        return res.status(404).json({ error: "Không tìm thấy loại sản phẩm." });
      }
  
      res.json({ categoryNews });
    } catch (error) {
      console.error(
        "Lỗi khi truy vấn loại sản phẩm theo ID:",
        error.message || error
      );
      res.status(500).json({ error: "Lỗi khi lấy loại sản phẩm." });
    }
  });
  
  app.post("/api/admin/categoryNews/them", async (req, res) => {
    const { name, status } = req.body;
  
    try {
      await CategoryNewsModel.create({
        name,
        status: status === undefined ? 0 : parseInt(status),
        created_at: new Date(),
        updated_at: new Date(),
      });
  
      res.status(200).json({ message: "Thêm loại tin thành công!" });
    } catch (error) {
      console.error("Lỗi khi thêm loại tin:", error.message || error);
      res.status(500).json({ error: "Lỗi khi thêm loại tin." });
    }
  });
  
  app.put("/api/admin/categoryNews/sua/:id", async (req, res) => {
    const { name, status } = req.body;
    const id = req.params.id;
  
    try {
      const updatedLoai = await CategoryNewsModel.findByIdAndUpdate(
        id,
        {
          name,
          status: status == undefined ? 0 : parseInt(status),
          updated_at: new Date(),
        },
        { new: true }
      );
  
      if (updatedLoai) {
        res.json({ message: "Cập nhật loại tin thành công!", loai: updatedLoai });
      } else {
        res.status(404).json({ error: "Không tìm thấy loại tin với ID này." });
      }
    } catch (error) {
      console.error("Lỗi khi cập nhật loại tin:", error);
      res.status(500).json({ error: "Lỗi khi cập nhật loại tin." });
    }
  });
  
  app.delete("/api/admin/categoryNews/xoa/:id", async (req, res) => {
    const id = req.params.id;
  
    try {
      const count = await NewsModel.countDocuments({ categorynews_id: id });
      if (count > 0) {
        return res.status(400).json({
          thong_bao: "Không thể xóa vì vẫn còn tin thuộc loại này.",
        });
      }
  
      const deleted = await CategoryNewsModel.findByIdAndDelete(id);
      if (deleted) {
        res.json({ message: "Xóa loại tin thành công!" });
      } else {
        res.status(404).json({ error: "Không tìm thấy loại tin với ID này." });
      }
    } catch (error) {
      console.error("Lỗi khi xóa loại tin:", error);
      res.status(500).json({ error: "Lỗi khi xóa loại tin." });
    }
  });
  // ! <== End Category News ==>
  
  // ! <== Voucher ==>
  app.get("/api/admin/voucher", async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
  
    try {
      const total = await VoucherModel.countDocuments();
      const list = await VoucherModel.find()
        .sort({ _id: -1 })
        .skip(skip)
        .limit(limit);
  
      res.json({ list, total });
      console.log(
        "Danh sách ID:",
        list.map((v) => v._id)
      );
    } catch (error) {
      console.error("Lỗi khi truy vấn cơ sở dữ liệu:", error);
      res.status(500).json({ error: "Lỗi khi lấy danh sách voucher." });
    }
  });
  
  app.get("/api/admin/voucher/:id", async (req, res) => {
    const voucherId = req.params.id;
  
    try {
      const voucher = await VoucherModel.findById(voucherId);
  
      if (!voucher) {
        return res.status(404).json({ error: "Không tìm thấy voucher." });
      }
  
      res.json({ voucher });
    } catch (error) {
      console.error("Lỗi khi truy vấn voucher theo ID:", error.message || error);
      res.status(500).json({ error: "Lỗi khi lấy voucher." });
    }
  });
  
  app.post("/api/admin/voucher/them", async (req, res) => {
    const {
      voucher_name,
      voucher_code,
      start_date,
      end_date,
      discount_type,
      discount_value,
      minimum_order_value,
      max_discount,
      status,
    } = req.body;
  
    try {
      const newVoucher = await VoucherModel.create({
        voucher_name,
        voucher_code,
        start_date,
        end_date,
        discount_type,
        discount_value,
        minimum_order_value: minimum_order_value || 0,
        max_discount: max_discount || null,
        status: status === undefined ? 0 : parseInt(status),
        created_at: new Date(),
        updated_at: new Date(),
      });
  
      res.json({
        message: "Thêm voucher thành công!",
        voucher: newVoucher,
      });
    } catch (error) {
      console.error("Lỗi khi thêm voucher:", error.message || error);
      res.status(500).json({ error: "Lỗi khi thêm voucher." });
    }
  });
  
  app.put("/api/admin/voucher/sua/:id", async (req, res) => {
    const id = req.params.id;
    const {
      voucher_name,
      voucher_code,
      start_date,
      end_date,
      discount_type,
      discount_value,
      minimum_order_value,
      max_discount,
      status,
    } = req.body;
  
    try {
      const updated = await VoucherModel.findByIdAndUpdate(
        id,
        {
          voucher_name,
          voucher_code,
          start_date,
          end_date,
          discount_type,
          discount_value,
          minimum_order_value: minimum_order_value || 0,
          max_discount: max_discount || null,
          status: status === undefined ? 0 : parseInt(status),
          updated_at: new Date(),
        },
        { new: true }
      );
  
      if (updated) {
        res.json({
          message: "Cập nhật voucher thành công!",
          voucher: updated,
        });
      } else {
        res.status(404).json({ error: "Không tìm thấy voucher với ID này." });
      }
    } catch (error) {
      console.error("Lỗi khi cập nhật voucher:", error.message || error);
      res.status(500).json({ error: "Lỗi khi cập nhật voucher." });
    }
  });
  
  app.delete("/api/admin/voucher/xoa/:id", async (req, res) => {
    const id = req.params.id;
  
    try {
      const deleted = await VoucherModel.findByIdAndDelete(id);
  
      if (deleted) {
        res.json({ message: "Xóa thành công!" });
      } else {
        res.status(404).json({ error: "Không tìm thấy voucher với ID này." });
      }
    } catch (error) {
      console.error("Lỗi khi xóa:", error);
      res.status(500).json({ error: "Lỗi khi xóa." });
    }
  });
  // ! <== End Voucher ==>
  
  // ! <== Brand ==>
  app.get("/api/admin/brand", async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
  
    try {
      const total = await BrandModel.countDocuments();
      const list = await BrandModel.find()
        .sort({ _id: -1 })
        .skip(skip)
        .limit(limit);
  
      res.json({ list, total });
    } catch (error) {
      console.error("Lỗi khi truy vấn thương hiệu:", error);
      res.status(500).json({ error: "Lỗi khi lấy danh sách thương hiệu." });
    }
  });
  
  app.get("/api/admin/brand/:id", async (req, res) => {
    const brandId = req.params.id;
  
    try {
      const brand = await BrandModel.findById(brandId);
  
      if (!brand) {
        return res.status(404).json({ error: "Không tìm thấy thương hiệu." });
      }
  
      res.json({ brand });
    } catch (error) {
      console.error(
        "Lỗi khi truy vấn thương hiệu theo ID:",
        error.message || error
      );
      res.status(500).json({ error: "Lỗi khi lấy thương hiệu." });
    }
  });
  
  app.post(
    "/api/admin/brand/them",
    uploadBrand.single("image"),
    async function (req, res) {
      const { name, alt, category_status, description } = req.body;
      const image = req.file ? `${req.file.filename}` : null;
  
      try {
        const newLoai = new BrandModel({
          name,
          image,
          alt,
          description,
          category_status:
            category_status === undefined ? 0 : parseInt(category_status),
          created_at: new Date(),
          updated_at: new Date(),
        });
  
        await newLoai.save();
        res.status(200).json({ message: "Thêm thương hiệu thành công!" });
      } catch (error) {
        console.error("Lỗi khi thêm thương hiệu:", error);
        res.status(500).json({ error: "Lỗi khi thêm thương hiệu." });
      }
    }
  );
  
  app.put(
    "/api/admin/brand/sua/:id",
    uploadBrand.single("image"),
    async function (req, res) {
      const id = req.params.id;
      const { name, alt, category_status, description } = req.body;
      const image = req.file ? `${req.file.filename}` : req.body.image_cu;
  
      try {
        const updatedLoai = await BrandModel.findByIdAndUpdate(
          id,
          {
            name,
            image,
            alt,
            description,
            category_status:
              category_status === undefined ? 0 : parseInt(category_status),
            updated_at: new Date(),
          },
          { new: true }
        );
  
        if (!mongoose.Types.ObjectId.isValid(id)) {
          return res.status(400).json({ error: "ID không hợp lệ." });
        }
  
        if (updatedLoai) {
          res.json({
            message: "Cập nhật thương hiệu thành công!",
            loai: updatedLoai,
          });
        } else {
          res.status(404).json({ error: "Không tìm thấy thương hiệu." });
        }
      } catch (error) {
        console.error("Chi tiết lỗi cập nhật:", error.message || error);
        res.status(500).json({ error: "Lỗi khi cập nhật thương hiệu." });
      }
    }
  );
  
  app.delete("/api/admin/brand/xoa/:id", async (req, res) => {
    const id = req.params.id;
  
    try {
      const count = await ProductModel.countDocuments({
        brand_id: id,
      });
      if (count > 0) {
        return res.status(400).json({
          thong_bao: "Không thể xóa vì vẫn còn sản phẩm thuộc thương hiệu này.",
        });
      }
  
      const deleted = await BrandModel.findByIdAndDelete(id);
  
      if (deleted) {
        res.json({ message: "Xóa thương hiệu thành công!" });
      } else {
        res.status(404).json({ error: "Không tìm thấy brand với ID này." });
      }
    } catch (error) {
      console.error("Lỗi khi xóa brand:", error);
      res.status(500).json({ error: "Lỗi khi xóa thương hiệu." });
    }
  });
  // ! <== End Brand ==>
  
  // ! <== Review ==>
  app.get("/api/admin/review", async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
  
    try {
      const total = await ReviewModel.countDocuments();
  
      const list = await ReviewModel.find()
        .sort({ _id: -1 })
        .skip(skip)
        .limit(limit)
        .populate({
          path: "user_id",
          model: "users",
          select: "username",
          populate: {
            path: "addresses",
            model: "address",
            select: "receiver_name",
          },
        })
        .populate({
          path: "order_detail_id",
          model: "order_details",
          select: "product_id",
          populate: {
            path: "product_id",
            model: "products",
            select: "name",
          },
        });
  
      const populatedList = await Promise.all(
        list.map(async (review) => {
          const productId = review?.order_detail_id?.product_id?._id;
          let main_image = null;
  
          if (productId) {
            main_image = await ProductImageModel.findOne({
              product_id: productId,
              is_main: true,
            }).select("image alt is_main");
          }
  
          return {
            ...review.toObject(),
            order_detail_id: {
              ...review.order_detail_id.toObject(),
              product_id: {
                ...review.order_detail_id.product_id.toObject(),
                main_image,
              },
            },
          };
        })
      );
  
      res.json({ list: populatedList, total });
    } catch (error) {
      console.error("Lỗi khi truy vấn reviews:", error);
      res.status(500).json({ error: "Lỗi khi lấy danh sách đánh giá." });
    }
  });
  // ! <== End Review ==>
  
  // ! <== Payment Method ==>
  app.get("/api/admin/payment-method", async function (req, res) {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
  
    try {
      const filter = { status: 0 };
      const total = await PaymentMethodModel.countDocuments(filter);
      const list = await PaymentMethodModel.find(filter)
        .sort({ _id: -1 })
        .skip(skip)
        .limit(limit);
  
      res.json({ list, total });
    } catch (error) {
      console.error("Lỗi khi lấy danh sách phương thức thanh toán:", error);
      res
        .status(500)
        .json({ error: "Lỗi khi lấy danh sách phương thức thanh toán." });
    }
  });
  
  app.get("/api/admin/payment-method/:id", async (req, res) => {
    const id = req.params.id;
  
    try {
      const payment = await PaymentMethodModel.findById(id);
      if (!payment) {
        return res
          .status(404)
          .json({ error: "Không tìm thấy phương thức thanh toán." });
      }
  
      res.json({ payment });
    } catch (error) {
      console.error("Lỗi khi lấy phương thức thanh toán theo ID:", error);
      res.status(500).json({ error: "Lỗi khi lấy phương thức thanh toán." });
    }
  });
  
  app.post("/api/admin/payment-method/them", async (req, res) => {
    const { name, code, description, status, is_active, icon_url } = req.body;
  
    try {
      const newPayment = await PaymentMethodModel.create({
        name,
        code,
        description,
        status: status == undefined ? 0 : +status,
        is_active: is_active !== undefined ? !!is_active : true,
        icon_url,
        created_at: new Date(),
        updated_at: new Date(),
      });
  
      res.status(201).json({
        message: "Thêm phương thức thanh toán thành công!",
        payment: newPayment,
      });
    } catch (error) {
      console.error("Lỗi khi thêm phương thức thanh toán:", error);
      res.status(500).json({ error: "Lỗi khi thêm phương thức thanh toán." });
    }
  });
  
  app.put("/api/admin/payment-method/sua/:id", async (req, res) => {
    const id = req.params.id;
    const { name, code, description, status, is_active, icon_url } = req.body;
  
    try {
      const updatedPayment = await PaymentMethodModel.findByIdAndUpdate(
        id,
        {
          name,
          code,
          description,
          status: status == undefined ? 0 : +status,
          is_active: is_active !== undefined ? !!is_active : true,
          icon_url,
          updated_at: new Date(),
        },
        { new: true }
      );
  
      if (!updatedPayment) {
        return res
          .status(404)
          .json({ error: "Không tìm thấy phương thức thanh toán." });
      }
  
      res.json({ message: "Cập nhật thành công!", payment: updatedPayment });
    } catch (error) {
      console.error("Lỗi khi cập nhật phương thức thanh toán:", error);
      res.status(500).json({ error: "Lỗi khi cập nhật phương thức thanh toán." });
    }
  });
  
  app.delete("/api/admin/payment-method/xoa/:id", async (req, res) => {
    const id = req.params.id;
  
    try {
      const deleted = await PaymentMethodModel.findByIdAndDelete(id);
  
      if (!deleted) {
        return res
          .status(404)
          .json({ error: "Không tìm thấy phương thức thanh toán." });
      }
  
      res.json({ message: "Xóa phương thức thanh toán thành công!" });
    } catch (error) {
      console.error("Lỗi khi xóa phương thức thanh toán:", error);
      res.status(500).json({ error: "Lỗi khi xóa phương thức thanh toán." });
    }
  });
  // ! <== End Payment Method ==>

  // API endpoint cho search suggestions
  app.get('/api/search/suggestions', async (req, res) => {
    try {
      const { q } = req.query;
      if (!q || q.length < 2) {
        return res.json({ suggestions: [] });
      }

      // Tìm kiếm trong products
      const products = await ProductModel.find({
        $or: [
          { name: { $regex: q, $options: 'i' } },
          { brand: { $regex: q, $options: 'i' } },
          { category: { $regex: q, $options: 'i' } }
        ]
      }).limit(5);

      // Tìm kiếm trong brands
      const brands = await BrandModel.find({
        name: { $regex: q, $options: 'i' }
      }).limit(3);

      // Tìm kiếm trong categories
      const categories = await CategoryModel.find({
        name: { $regex: q, $options: 'i' }
      }).limit(3);

      const suggestions = [
        ...products.map(p => ({ name: p.name, type: 'product' })),
        ...brands.map(b => ({ name: b.name, type: 'brand' })),
        ...categories.map(c => ({ name: c.name, type: 'category' }))
      ];

      res.json({ suggestions });
    } catch (error) {
      console.error('Search suggestions error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // API endpoint cho search chính
  app.get('/api/search', async (req, res) => {
    try {
      const { q, brand, category, priceRange, sortBy } = req.query;
      
      let query = {};
      
      // Tìm kiếm theo từ khóa
      if (q) {
        query.$or = [
          { name: { $regex: q, $options: 'i' } },
          { description: { $regex: q, $options: 'i' } },
          { brand: { $regex: q, $options: 'i' } },
          { category: { $regex: q, $options: 'i' } }
        ];
      }

      // Filter theo brand
      if (brand) {
        query.brand = { $regex: brand, $options: 'i' };
      }

      // Filter theo category
      if (category) {
        query.category = { $regex: category, $options: 'i' };
      }

      // Filter theo price range
      if (priceRange) {
        const [min, max] = priceRange.split('-');
        if (max === '+') {
          query.price = { $gte: parseInt(min) };
        } else {
          query.price = { $gte: parseInt(min), $lte: parseInt(max) };
        }
      }

      // Sort options
      let sort = {};
      switch (sortBy) {
        case 'price-asc':
          sort = { price: 1 };
          break;
        case 'price-desc':
          sort = { price: -1 };
          break;
        case 'name-asc':
          sort = { name: 1 };
          break;
        default:
          sort = { createdAt: -1 };
      }

      const products = await ProductModel.find(query)
        .sort(sort)
        .limit(50)
        .lean(); // Sử dụng lean() để tối ưu performance

      // Lấy ảnh cho từng sản phẩm
      const productsWithImages = await Promise.all(
        products.map(async (product) => {
          const images = await ProductImageModel.find({ 
            product_id: product._id 
          }).sort({ is_main: -1 }).lean(); // Sắp xếp ảnh chính lên đầu
          
          return {
            ...product,
            images: images.map(img => img.image)
          };
        })
      );

      res.json({ products: productsWithImages });
    } catch (error) {
      console.error('Search error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // API lấy danh mục tin tức cho client
  app.get('/api/category-news', async (req, res) => {
    try {
      const categories = await CategoryNewsModel.find({ status: 0 }) // Chỉ lấy danh mục đang hoạt động
        .sort({ created_at: -1 });
      res.json(categories);
    } catch (err) {
      res.status(500).json({ error: 'Lỗi lấy danh mục tin tức', details: err });
    }
  });

  app.post('/request-password-reset',
    body('email').isEmail().withMessage('Email không hợp lệ.'),
    async (req, res) => {
      try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
          return res.status(400).json({ message: errors.array()[0].msg });
        }

        const { email } = req.body;
        const user = await User.findOne({ email: email, account_status: '1' });

        if (!user) {
          return res.status(404).json({ message: 'Không tìm thấy tài khoản hoạt động với email này.' });
        }

        const resetToken = Math.floor(100000 + Math.random() * 900000).toString();
        user.passwordResetToken = resetToken;
        user.passwordResetTokenExpires = new Date(Date.now() + 10 * 60 * 1000); // Hết hạn sau 10 phút
        await user.save();

        const mailOptions = {
          from: `"V.CLOCK" <${process.env.EMAIL_USER}>`,
          to: user.email,
          subject: 'Yêu cầu đặt lại mật khẩu cho tài khoản V.CLOCK',
          html: `<p>Chào bạn,</p>
                 <p>Chúng tôi nhận được yêu cầu đặt lại mật khẩu cho tài khoản của bạn. Mã OTP để đặt lại mật khẩu là:</p>
                 <h2 style="text-align:center;color:#d9534f;">${resetToken}</h2>
                 <p>Mã này sẽ hết hạn trong 10 phút. Nếu bạn không yêu cầu, vui lòng bỏ qua email này.</p>
                 <p>Trân trọng,<br/>Đội ngũ V.CLOCK</p>`,
        };

        await transporter.sendMail(mailOptions);

        res.status(200).json({ message: 'Yêu cầu thành công. Vui lòng kiểm tra email để lấy mã OTP.' });

      } catch (error) {
        console.error('Request password reset error:', error);
        res.status(500).json({ message: 'Lỗi server', error: error.message });
      }
  });

  app.post('/reset-password',
    body('email').isEmail().withMessage('Email không hợp lệ.'),
    body('otp').isLength({ min: 6, max: 6 }).withMessage('Mã OTP phải có 6 chữ số.'),
    body('newPassword').isLength({ min: 6 }).withMessage('Mật khẩu mới phải có ít nhất 6 ký tự.'),
    async (req, res) => {
      try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
          return res.status(400).json({ message: errors.array()[0].msg });
        }
        
        const { email, otp, newPassword } = req.body;

        const user = await User.findOne({
          email: email,
          passwordResetToken: otp,
          passwordResetTokenExpires: { $gt: Date.now() },
        });

        if (!user) {
          return res.status(400).json({ message: 'Mã OTP không hợp lệ hoặc đã hết hạn.' });
        }

        const saltRounds = 10;
        user.password_hash = await bcrypt.hash(newPassword, saltRounds);
        user.passwordResetToken = null;
        user.passwordResetTokenExpires = null;
        await user.save();

        res.status(200).json({ message: 'Mật khẩu đã được đặt lại thành công. Bạn có thể đăng nhập ngay bây giờ.' });

      } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ message: 'Lỗi server', error: error.message });
      }
  });

  // API endpoint cho contact form
  app.post('/api/contact',
    body('name').notEmpty().withMessage('Tên không được để trống.'),
    body('email').isEmail().withMessage('Email không hợp lệ.'),
    body('message').notEmpty().withMessage('Nội dung tin nhắn không được để trống.'),
    async (req, res) => {
      try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
          return res.status(400).json({ message: errors.array()[0].msg });
        }

        const { name, email, phone, company, message } = req.body;

        // Gửi email đến admin
        const adminMailOptions = {
          from: `"V.CLOCK Contact Form" <${process.env.EMAIL_USER}>`,
          to: process.env.EMAIL_USER, // Email admin
          subject: 'Tin nhắn liên hệ mới từ V.CLOCK',
          html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
              <h2 style="color: #d9534f; border-bottom: 2px solid #d9534f; padding-bottom: 10px;">
                Tin Nhắn Liên Hệ Mới
              </h2>
              
              <div style="background-color: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
                <h3 style="color: #333; margin-top: 0;">Thông Tin Người Gửi:</h3>
                <p><strong>Họ và Tên:</strong> ${name}</p>
                <p><strong>Email:</strong> ${email}</p>
                ${phone ? `<p><strong>Số Điện Thoại:</strong> ${phone}</p>` : ''}
                ${company ? `<p><strong>Công Ty:</strong> ${company}</p>` : ''}
              </div>

              <div style="background-color: #fff; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
                <h3 style="color: #333; margin-top: 0;">Nội Dung Tin Nhắn:</h3>
                <p style="line-height: 1.6; white-space: pre-wrap;">${message}</p>
              </div>

              <div style="margin-top: 20px; padding: 15px; background-color: #e9ecef; border-radius: 8px;">
                <p style="margin: 0; color: #666; font-size: 14px;">
                  <strong>Thời gian:</strong> ${new Date().toLocaleString('vi-VN')}<br>
                  <strong>IP:</strong> ${req.ip}<br>
                  <strong>User Agent:</strong> ${req.get('User-Agent')}
                </p>
              </div>
            </div>
          `,
        };

        // Gửi email xác nhận cho khách hàng
        const customerMailOptions = {
          from: `"V.CLOCK" <${process.env.EMAIL_USER}>`,
          to: email,
          subject: 'Xác nhận tin nhắn liên hệ - V.CLOCK',
          html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
              <h2 style="color: #d9534f; border-bottom: 2px solid #d9534f; padding-bottom: 10px;">
                Xác Nhận Tin Nhắn Liên Hệ
              </h2>
              
              <p>Chào <strong>${name}</strong>,</p>
              
              <p>Cảm ơn bạn đã liên hệ với V.CLOCK. Chúng tôi đã nhận được tin nhắn của bạn và sẽ phản hồi trong thời gian sớm nhất.</p>
              
              <div style="background-color: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
                <h3 style="color: #333; margin-top: 0;">Thông Tin Tin Nhắn:</h3>
                <p><strong>Thời gian gửi:</strong> ${new Date().toLocaleString('vi-VN')}</p>
                <p><strong>Nội dung:</strong></p>
                <div style="background-color: #fff; padding: 15px; border: 1px solid #ddd; border-radius: 5px; margin-top: 10px;">
                  <p style="line-height: 1.6; white-space: pre-wrap; margin: 0;">${message}</p>
                </div>
              </div>

              <p>Nếu bạn có bất kỳ câu hỏi nào khác, vui lòng liên hệ với chúng tôi qua:</p>
              <ul>
                <li>Email: contact@vclock.vn</li>
                <li>Điện thoại: 0909 123 456</li>
                <li>Địa chỉ: 1073/23 Cách Mạng Tháng 8, Phường 7, Quận Tân Bình, TP. Hồ Chí Minh</li>
              </ul>

              <p style="margin-top: 30px; color: #666; font-size: 14px;">
                Trân trọng,<br>
                <strong>Đội ngũ V.CLOCK</strong>
              </p>
            </div>
          `,
        };

        // Gửi cả hai email
        await Promise.all([
          transporter.sendMail(adminMailOptions),
          transporter.sendMail(customerMailOptions)
        ]);

        res.status(200).json({ 
          message: 'Tin nhắn của bạn đã được gửi thành công! Chúng tôi sẽ liên hệ lại sớm.',
          success: true 
        });

      } catch (error) {
        console.error('Contact form error:', error);
        res.status(500).json({ 
          message: 'Có lỗi xảy ra khi gửi tin nhắn. Vui lòng thử lại sau.',
          error: error.message 
        });
      }
  });

app.listen(port, () => console.log(`Ung dung dang chay voi port ${port}`));