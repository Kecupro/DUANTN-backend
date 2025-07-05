const mongoose = require("mongoose");
const productCategoriesSchema = require("./model/schemaproductCategories");
const productSchema = require("./model/schemaProduct");
const categorySchema = require("./model/schemaCategory");

const MONGO_URI = "mongodb://127.0.0.1:27017/DATN_V2";

const chen_product_category = async () => {
  try {
    // Kết nối tới MongoDB
    await mongoose.connect(MONGO_URI);
    console.log("Đã kết nối tới MongoDB.");

    const ProductCategoryModel = mongoose.model("product_categories", productCategoriesSchema);
    const ProductModel = mongoose.model("products", productSchema);
    const CategoryModel = mongoose.model("categories", categorySchema);

    // 1. Lấy tất cả sản phẩm và danh mục
    const allProducts = await ProductModel.find().select("_id");
    const allCategories = await CategoryModel.find().select("_id");

    if (allProducts.length === 0 || allCategories.length === 0) {
      console.log("Không có sản phẩm hoặc danh mục nào để xử lý. Vui lòng tạo dữ liệu cho chúng trước.");
      return;
    }
    
    // 2. Xóa dữ liệu cũ
    const { deletedCount } = await ProductCategoryModel.deleteMany({});
    console.log(`Đã xóa ${deletedCount} bản ghi cũ từ product_categories.`);

    // 3. Tạo các mối quan hệ mới
    const productCategoryLinks = [];
    for (const product of allProducts) {
      // Số lượng danh mục ngẫu nhiên cho mỗi sản phẩm (từ 1 đến 3)
      const categoryCount = Math.floor(Math.random() * 3) + 1;
      
      // Lấy danh sách ID danh mục xáo trộn
      const shuffledCategories = [...allCategories].sort(() => 0.5 - Math.random());

      for (let i = 0; i < categoryCount; i++) {
        if (shuffledCategories[i]) {
          productCategoryLinks.push({
            product_id: product._id,
            category_id: shuffledCategories[i]._id,
          });
        }
      }
    }

    // 4. Chèn tất cả các mối quan hệ vào CSDL
    if (productCategoryLinks.length > 0) {
      await ProductCategoryModel.insertMany(productCategoryLinks);
      console.log(`Đã chèn thành công ${productCategoryLinks.length} mối quan hệ sản phẩm-danh mục.`);
    } else {
      console.log("Không có mối quan hệ nào được tạo.");
    }

  } catch (error) {
    console.error("Đã xảy ra lỗi:", error);
  } finally {
    // 5. Đóng kết nối
    await mongoose.disconnect();
    console.log("Đã ngắt kết nối khỏi MongoDB.");
  }
};

// Chạy hàm
chen_product_category(); 