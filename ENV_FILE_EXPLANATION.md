# 📄 Environment File Explanation

**Câu hỏi:** Pipeline đang sử dụng file `.env` hay `env.template`?

---

## ✅ TRẢ LỜI

**Pipeline sử dụng file `.env` (KHÔNG phải `env.template`)**

---

## 🔍 CHI TIẾT

### **1. Code Load Environment Variables:**

**File:** `src/common/config.py`
```python
from dotenv import load_dotenv

# Load .env file
load_dotenv()
```

**Giải thích:**
- ✅ `load_dotenv()` tự động tìm và load file `.env` từ project root
- ✅ `env.template` KHÔNG được load trực tiếp
- ✅ `env.template` chỉ là template file để user copy thành `.env`

---

### **2. Thứ tự ưu tiên:**

1. **File `.env`** (nếu có) → Được load bởi `load_dotenv()`
2. **System environment variables** → Nếu không có trong `.env`
3. **Default values** → Nếu không có trong cả hai

---

### **3. Cách hoạt động:**

#### **Nếu có file `.env`:**
```bash
# Pipeline sẽ load từ .env
WAZUH_INDEXER_VERIFY_SSL=false  # ← Từ .env
```

#### **Nếu KHÔNG có file `.env`:**
```bash
# Pipeline sẽ dùng default values hoặc system env vars
WAZUH_INDEXER_VERIFY_SSL=true  # ← Default từ code
```

---

## 📋 KIỂM TRA

### **1. Kiểm tra file `.env` có tồn tại không:**

```bash
# Windows PowerShell:
Test-Path .env

# Hoặc:
dir .env
```

**Kết quả:**
- ✅ **Có file `.env`** → Pipeline sẽ load từ file này
- ❌ **Không có file `.env`** → Pipeline sẽ dùng default values

---

### **2. Kiểm tra file `env.template`:**

```bash
# Windows PowerShell:
Test-Path env.template

# Hoặc:
dir env.template
```

**Kết quả:**
- ✅ **Có file `env.template`** → Chỉ là template, KHÔNG được load
- ❌ **Không có file `env.template`** → Không sao, chỉ là template

---

## 🔧 CÁCH SỬ DỤNG

### **Option 1: Tạo file `.env` từ `env.template`:**

```bash
# Windows PowerShell:
Copy-Item env.template .env

# Hoặc:
copy env.template .env
```

**Sau đó chỉnh sửa `.env` theo nhu cầu:**
```bash
WAZUH_INDEXER_VERIFY_SSL=false
WAZUH_START_FROM_NOW=true
WAZUH_LOOKBACK_MINUTES=5
```

---

### **Option 2: Tạo file `.env` mới:**

```bash
# Tạo file .env mới
New-Item .env -ItemType File

# Hoặc:
type nul > .env
```

**Sau đó thêm các biến cần thiết:**
```bash
WAZUH_INDEXER_VERIFY_SSL=false
WAZUH_START_FROM_NOW=true
WAZUH_LOOKBACK_MINUTES=5
```

---

## ⚠️ LƯU Ý

### **1. File `.env` thường bị gitignore:**

```bash
# Kiểm tra .gitignore:
cat .gitignore | grep .env
```

**Lý do:**
- ✅ `.env` chứa thông tin nhạy cảm (API keys, passwords)
- ✅ Không nên commit vào git
- ✅ Mỗi developer/environment có `.env` riêng

---

### **2. `env.template` được commit vào git:**

**Lý do:**
- ✅ Chỉ là template, không chứa thông tin nhạy cảm
- ✅ Giúp developer biết cần set biến gì
- ✅ Có thể commit vào git an toàn

---

## 🎯 KẾT LUẬN

### **Pipeline sử dụng:**
- ✅ **File `.env`** (nếu có) → Được load bởi `load_dotenv()`
- ❌ **File `env.template`** → KHÔNG được load, chỉ là template

### **Để fix lỗi SSL:**
1. **Tạo file `.env`** (nếu chưa có):
   ```bash
   Copy-Item env.template .env
   ```

2. **Thêm hoặc sửa trong `.env`:**
   ```bash
   WAZUH_INDEXER_VERIFY_SSL=false
   ```

3. **Chạy lại pipeline:**
   ```bash
   py -3 bin\run_pipeline.py
   ```

---

## 📊 SO SÁNH

| File | Được load? | Mục đích | Commit vào git? |
|------|-----------|----------|-----------------|
| `.env` | ✅ **CÓ** | Chứa config thực tế | ❌ Không (gitignore) |
| `env.template` | ❌ **KHÔNG** | Template để copy | ✅ Có (an toàn) |

---

## 🔍 DEBUG

### **Kiểm tra file nào đang được load:**

**Thêm log vào `src/common/config.py`:**
```python
from dotenv import load_dotenv
import os

# Load .env file
result = load_dotenv()
print(f"load_dotenv() result: {result}")
print(f".env file exists: {os.path.exists('.env')}")
print(f"env.template exists: {os.path.exists('env.template')}")
```

**Kết quả:**
- `load_dotenv() result: True` → File `.env` được load thành công
- `load_dotenv() result: False` → Không có file `.env` hoặc không load được

---

## ✅ TÓM TẮT

1. **Pipeline sử dụng file `.env`** (không phải `env.template`)
2. **`env.template` chỉ là template** để user copy thành `.env`
3. **Nếu không có `.env`** → Pipeline dùng default values
4. **Để fix lỗi SSL** → Tạo `.env` và set `WAZUH_INDEXER_VERIFY_SSL=false`

