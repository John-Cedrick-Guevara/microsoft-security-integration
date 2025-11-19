# SafeVault - Quick Start Guide

## 🚀 Get Started in 5 Minutes

### Step 1: Restore Dependencies

```powershell
cd "d:\2025 code shits lock in - Copy\microsoft projects\Secure"
dotnet restore
```

### Step 2: Run Security Tests

```powershell
dotnet test
```

**Expected Output**: 31 tests pass (100% success rate)

### Step 3: Start the Application

```powershell
dotnet run
```

**Access**: Navigate to `https://localhost:5001` in your browser

### Step 4: Test Security Features

#### Test SQL Injection Protection

1. Go to the registration form
2. Enter username: `admin' OR '1'='1`
3. Enter email: `test@example.com`
4. Click "Register Securely"
5. **Result**: ❌ "SQL commands are not allowed"

#### Test XSS Protection

1. Go to the registration form
2. Enter username: `<script>alert('XSS')</script>`
3. Enter email: `test@example.com`
4. Click "Register Securely"
5. **Result**: ❌ "Script tags and HTML are not allowed"

#### Test Valid Registration

1. Go to the registration form
2. Enter username: `john_doe`
3. Enter email: `john@example.com`
4. Click "Register Securely"
5. **Result**: ✅ "Registration successful! Welcome, john_doe!"

## 📋 What You Get

### ✅ Secure Features

- SQL Injection Prevention (parameterized queries)
- XSS Prevention (input sanitization + output encoding)
- CSRF Protection (anti-forgery tokens)
- HTTPS Enforcement
- Security Headers (CSP, X-Frame-Options, etc.)
- Comprehensive Logging

### ✅ Testing Suite

- 31 automated security tests
- XSS attack simulations
- SQL injection attack simulations
- Input validation tests
- Integration tests

### ✅ Documentation

- **README.md**: Complete project overview
- **SECURITY.md**: Detailed security implementation guide
- **PROJECT_SUMMARY.md**: File listing and statistics

## 🎯 Try These Attack Patterns

The application is designed to safely reject these:

### SQL Injection Attempts

```
admin' OR '1'='1
'; DROP TABLE Users; --
1' UNION SELECT * FROM Users--
admin'--
' OR 1=1--
```

### XSS Attempts

```
<script>alert('XSS')</script>
<img src=x onerror=alert(1)>
<body onload=alert('XSS')>
javascript:alert('XSS')
<div onclick='alert(1)'>Click</div>
```

All will be **detected and rejected** with appropriate error messages!

## 📊 Verify Test Results

Run tests by category:

```powershell
# All tests
dotnet test

# XSS tests only
dotnet test --filter "Category=XSS"

# SQL Injection tests only
dotnet test --filter "Category=SQLInjection"

# Security tests
dotnet test --filter "Category=Security"

# Validation tests
dotnet test --filter "Category=Validation"
```

## 🔍 Project Structure

```
Secure/
├── Controllers/        # Secure MVC controllers
├── Data/              # Entity Framework DbContext
├── Models/            # Data models with validation
├── Services/          # Business logic with security
├── Utilities/         # InputSanitizer utility
├── Views/             # Razor views with encoding
├── Tests/             # 31 security tests
└── Documentation/     # README, SECURITY, etc.
```

## 🛡️ Security Layers

1. **Client-Side**: HTML5 validation + JavaScript
2. **Model Validation**: Data annotations
3. **Input Sanitization**: InputSanitizer utility
4. **Parameterized Queries**: Entity Framework Core
5. **Output Encoding**: Razor automatic encoding

## 📚 Learn More

- **README.md**: Full project documentation
- **SECURITY.md**: Detailed security implementation
- **PROJECT_SUMMARY.md**: Complete file listing
- **Inline Comments**: Extensive security-focused comments in code

## 🎓 Key Takeaways

### SQL Injection Prevention

✅ **Always use parameterized queries**

```csharp
// ✅ SECURE
var user = await _context.Users
    .Where(u => u.Username == username)
    .FirstOrDefaultAsync();

// ❌ NEVER DO THIS
var query = "SELECT * FROM Users WHERE Username = '" + username + "'";
```

### XSS Prevention

✅ **Always sanitize input and encode output**

```csharp
// ✅ SECURE - Sanitize before storage
string safe = InputSanitizer.SanitizeForXss(userInput);

// ✅ SECURE - Razor auto-encodes
<div>@Model.Username</div>

// ❌ NEVER DO THIS
<div>@Html.Raw(Model.Username)</div>
```

## 🔐 Production Checklist

Before deploying to production:

- [ ] Replace in-memory database with SQL Server
- [ ] Update connection string in appsettings.json
- [ ] Enable detailed logging
- [ ] Configure Azure Key Vault
- [ ] Set up monitoring
- [ ] Run penetration testing
- [ ] Review security headers
- [ ] Enable rate limiting
- [ ] Set up WAF (Web Application Firewall)

## 💡 Tips

1. **Test Thoroughly**: Run all 31 tests before deployment
2. **Monitor Logs**: Check for security event patterns
3. **Keep Updated**: Update NuGet packages regularly
4. **Review Code**: Security review before changes
5. **Document Changes**: Update security documentation

## 🆘 Troubleshooting

### Tests Fail

```powershell
# Clean and rebuild
dotnet clean
dotnet build
dotnet test
```

### App Won't Start

```powershell
# Check port availability
netstat -ano | findstr :5001

# Use different port
dotnet run --urls "https://localhost:5002"
```

### Build Errors

```powershell
# Restore packages
dotnet restore

# Clear NuGet cache
dotnet nuget locals all --clear
dotnet restore
```

## 📞 Next Steps

1. ✅ Run the application
2. ✅ Test security features
3. ✅ Review the code
4. ✅ Read documentation
5. ✅ Customize for your needs

---

**🎉 You're all set! Enjoy your secure web application!**

For detailed information, see:

- **README.md** - Complete project guide
- **SECURITY.md** - Security implementation details
- **PROJECT_SUMMARY.md** - File listings and statistics
