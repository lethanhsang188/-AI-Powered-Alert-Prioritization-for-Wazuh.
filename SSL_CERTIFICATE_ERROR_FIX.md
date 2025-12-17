# 🔒 SSL Certificate Error - Giải Pháp

**Ngày:** 2025-12-14  
**Lỗi:** `[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate`

---

## 🔍 PHÂN TÍCH LỖI

### **Lỗi trong log:**
```
SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] 
certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)'))
```

**Nguyên nhân:**
- ❌ Pipeline đang cố verify SSL certificate của Wazuh Indexer
- ❌ Certificate không được trust (self-signed hoặc không có trong system CA store)
- ❌ `WAZUH_INDEXER_VERIFY_SSL` có thể đang set là `true` trong `.env`

---

## ✅ GIẢI PHÁP

### **Option 1: Disable SSL Verification (RECOMMENDED cho testing)**

**Thêm vào `.env` file:**
```bash
WAZUH_INDEXER_VERIFY_SSL=false
```

**Sau đó chạy lại pipeline:**
```bash
py -3 bin\run_pipeline.py
```

**Kết quả:**
- ✅ Pipeline sẽ bỏ qua SSL certificate verification
- ✅ Có warning: "Wazuh indexer SSL verification disabled"
- ✅ Pipeline sẽ hoạt động bình thường

---

### **Option 2: Sử dụng Custom Certificate (Production)**

**Nếu bạn có certificate file:**

1. **Copy certificate file vào project:**
   ```bash
   # Ví dụ: cert/wazuh/wazuh-indexer.crt
   ```

2. **Set trong `.env`:**
   ```bash
   WAZUH_INDEXER_VERIFY_SSL=cert/wazuh/wazuh-indexer.crt
   ```

3. **Chạy lại pipeline:**
   ```bash
   py -3 bin\run_pipeline.py
   ```

**Kết quả:**
- ✅ Pipeline sẽ verify với custom certificate
- ✅ An toàn hơn (verify certificate thay vì disable)

---

### **Option 3: Trust Certificate trong System (Advanced)**

**Nếu bạn muốn trust certificate trong system:**

1. **Export certificate từ Wazuh Indexer:**
   ```bash
   # Ví dụ: openssl s_client -connect 192.168.10.128:9200 -showcerts
   ```

2. **Add certificate vào system CA store:**
   ```bash
   # Windows: Import vào Certificate Store
   # Linux: Copy vào /etc/ssl/certs/
   ```

3. **Set trong `.env`:**
   ```bash
   WAZUH_INDEXER_VERIFY_SSL=true
   ```

**Kết quả:**
- ✅ Pipeline sẽ verify với system CA store
- ✅ An toàn nhất (verify certificate với system trust)

---

## 🔧 KIỂM TRA CẤU HÌNH HIỆN TẠI

### **Kiểm tra `.env` file:**
```bash
# Tìm dòng này:
WAZUH_INDEXER_VERIFY_SSL=...

# Nếu không có hoặc =true → Set =false
WAZUH_INDEXER_VERIFY_SSL=false
```

### **Kiểm tra `env.template`:**
```bash
# Default trong env.template:
WAZUH_INDEXER_VERIFY_SSL=true
```

**Nếu bạn copy từ `env.template` → Cần set `false` trong `.env`**

---

## 📋 CÁC GIÁ TRỊ HỢP LỆ

### **Boolean:**
- `true`, `1`, `yes`, `on`, `enable`, `enabled` → Enable SSL verification
- `false`, `0`, `no`, `off`, `disable`, `disabled` → Disable SSL verification

### **File Path:**
- Đường dẫn đến certificate file (ví dụ: `cert/wazuh/wazuh-indexer.crt`)

---

## ⚠️ LƯU Ý

### **Cho Testing/Development:**
- ✅ **Nên dùng:** `WAZUH_INDEXER_VERIFY_SSL=false`
- ⚠️ **Không an toàn** nhưng OK cho testing

### **Cho Production:**
- ✅ **Nên dùng:** Custom certificate hoặc system CA store
- ⚠️ **An toàn hơn** (verify certificate)

---

## 🎯 QUICK FIX

**Cách nhanh nhất để fix lỗi:**

1. **Mở `.env` file:**
   ```bash
   # Tìm dòng WAZUH_INDEXER_VERIFY_SSL
   ```

2. **Set giá trị:**
   ```bash
   WAZUH_INDEXER_VERIFY_SSL=false
   ```

3. **Lưu file và chạy lại:**
   ```bash
   py -3 bin\run_pipeline.py
   ```

**Kết quả:** Pipeline sẽ hoạt động bình thường! ✅

---

## 📊 LOG SAU KHI FIX

**Sau khi set `WAZUH_INDEXER_VERIFY_SSL=false`, bạn sẽ thấy:**

```
WARNING: Wazuh indexer SSL verification disabled. 
Enable WAZUH_INDEXER_VERIFY_SSL for production deployments.
```

**Đây là warning bình thường, không phải lỗi!** ✅

---

## 🔍 DEBUG

### **Nếu vẫn còn lỗi:**

1. **Kiểm tra `.env` file có được load không:**
   ```bash
   # Đảm bảo file `.env` nằm cùng thư mục với `bin/run_pipeline.py`
   ```

2. **Kiểm tra giá trị trong code:**
   ```python
   # Thêm log trong src/common/config.py:
   print(f"WAZUH_INDEXER_VERIFY_SSL: {WAZUH_INDEXER_VERIFY_SSL}")
   ```

3. **Kiểm tra session.verify:**
   ```python
   # Thêm log trong src/collector/wazuh_client.py:
   print(f"Indexer session.verify: {self.indexer_session.verify}")
   ```

---

## ✅ KẾT LUẬN

**Giải pháp đơn giản nhất:**
```bash
# Thêm vào .env
WAZUH_INDEXER_VERIFY_SSL=false
```

**Sau đó chạy lại pipeline → Sẽ hoạt động!** ✅

