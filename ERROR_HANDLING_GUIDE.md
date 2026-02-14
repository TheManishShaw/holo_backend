# Error Handling Best Practices - Implementation Guide

## Overview
This document outlines the improved error handling implemented across all APIs to provide clear, user-friendly error messages.

## Key Improvements

### 1. **Descriptive Error Messages**
- All error messages now clearly explain what went wrong
- Messages guide users on how to fix the issue
- No technical jargon in user-facing messages

### 2. **Proper HTTP Status Codes**
- `400` - Bad Request (validation errors, missing fields)
- `401` - Unauthorized (authentication required, invalid token)
- `404` - Not Found (resource doesn't exist)
- `409` - Conflict (duplicate email/phone)
- `500` - Internal Server Error (unexpected errors)

### 3. **Consistent Response Format**
```json
{
  "status": boolean,
  "message": "User-friendly message",
  "data": null | object
}
```

## API Error Responses

### POST /api/auth/register

#### Missing Fields
```json
{
  "status": false,
  "message": "Missing required fields: fullName, password. Please provide all required information.",
  "data": null
}
```

#### Invalid Email
```json
{
  "status": false,
  "message": "Please provide a valid email address.",
  "data": null
}
```

#### Short Password
```json
{
  "status": false,
  "message": "Password must be at least 6 characters long.",
  "data": null
}
```

#### Invalid Phone
```json
{
  "status": false,
  "message": "Please provide a valid phone number.",
  "data": null
}
```

#### Duplicate Email
```json
{
  "status": false,
  "message": "This email is already registered. Please use a different email or try logging in.",
  "data": null
}
```

#### Duplicate Phone
```json
{
  "status": false,
  "message": "This phone number is already registered. Please use a different number or try logging in.",
  "data": null
}
```

#### Success
```json
{
  "status": true,
  "message": "Account created successfully! You are now logged in.",
  "data": {
    "_id": "...",
    "fullName": "...",
    "email": "...",
    "phoneNumber": "...",
    "token": "..."
  }
}
```

---

### POST /api/auth/login

#### Missing Fields
```json
{
  "status": false,
  "message": "Please provide email and password to log in.",
  "data": null
}
```

#### Invalid Email Format
```json
{
  "status": false,
  "message": "Please provide a valid email address.",
  "data": null
}
```

#### User Not Found
```json
{
  "status": false,
  "message": "No account found with this email. Please check your email or sign up.",
  "data": null
}
```

#### Wrong Password
```json
{
  "status": false,
  "message": "Incorrect password. Please try again or reset your password.",
  "data": null
}
```

#### Success
```json
{
  "status": true,
  "message": "Login successful! Welcome back.",
  "data": {
    "_id": "...",
    "fullName": "...",
    "email": "...",
    "token": "..."
  }
}
```

---

### GET /api/auth/me

#### No Token
```json
{
  "status": false,
  "message": "Access denied. Please provide an authentication token to continue.",
  "data": null
}
```

#### Invalid Token
```json
{
  "status": false,
  "message": "Invalid authentication token. Please log in again.",
  "data": null
}
```

#### Expired Token
```json
{
  "status": false,
  "message": "Your session has expired. Please log in again.",
  "data": null
}
```

#### User Not Found
```json
{
  "status": false,
  "message": "User account not found. Your account may have been deleted.",
  "data": null
}
```

#### Success
```json
{
  "status": true,
  "message": "Profile retrieved successfully.",
  "data": {
    "id": "...",
    "fullName": "...",
    "email": "...",
    "phoneNumber": "..."
  }
}
```

---

### POST /api/auth/forgot-password

#### Missing Email
```json
{
  "status": false,
  "message": "Please provide your email address to reset your password.",
  "data": null
}
```

#### Invalid Email Format
```json
{
  "status": false,
  "message": "Please provide a valid email address.",
  "data": null
}
```

#### Success (Security: Same response whether user exists or not)
```json
{
  "status": true,
  "message": "A 6-digit verification code has been sent to your email. Please check your inbox and enter the code to reset your password.",
  "data": null
}
```

#### Email Send Failure
```json
{
  "status": false,
  "message": "Unable to send verification code. Please check your email address and try again.",
  "data": null
}
```

---

### POST /api/auth/verify-otp

#### Missing Fields
```json
{
  "status": false,
  "message": "Please provide email and verification code to verify.",
  "data": null
}
```

#### Invalid OTP Format
```json
{
  "status": false,
  "message": "Verification code must be a 6-digit number.",
  "data": null
}
```

#### Invalid OTP
```json
{
  "status": false,
  "message": "Invalid verification code. Please check the code and try again.",
  "data": null
}
```

#### Expired OTP
```json
{
  "status": false,
  "message": "This verification code has expired. Please request a new code.",
  "data": null
}
```

#### Already Used OTP
```json
{
  "status": false,
  "message": "This verification code has already been used. Please request a new code.",
  "data": null
}
```

#### Success
```json
{
  "status": true,
  "message": "Verification successful! You can now reset your password.",
  "data": {
    "resetToken": "..."
  }
}
```

---

### POST /api/auth/reset-password

#### Missing Fields
```json
{
  "status": false,
  "message": "Please provide reset token and new password to reset your password.",
  "data": null
}
```

#### Short Password
```json
{
  "status": false,
  "message": "New password must be at least 6 characters long.",
  "data": null
}
```

#### Invalid Token
```json
{
  "status": false,
  "message": "Invalid reset token. Please request a new verification code.",
  "data": null
}
```

#### Expired Token
```json
{
  "status": false,
  "message": "Your password reset session has expired. Please request a new verification code.",
  "data": null
}
```

#### User Not Found
```json
{
  "status": false,
  "message": "Account not found. Please contact support if you need assistance.",
  "data": null
}
```

#### Success
```json
{
  "status": true,
  "message": "Password reset successfully! You can now log in with your new password.",
  "data": null
}
```

---

### POST /api/auth/check-registered

#### No Token
```json
{
  "status": false,
  "message": "Access denied. Please provide an authentication token to continue.",
  "data": null
}
```

#### Invalid Token
```json
{
  "status": false,
  "message": "Invalid authentication token. Please log in again.",
  "data": null
}
```

#### Missing Identifiers
```json
{
  "status": false,
  "message": "Please provide an 'identifiers' array containing emails or phone numbers to check.",
  "data": null
}
```

#### Invalid Type (Not Array)
```json
{
  "status": false,
  "message": "The 'identifiers' field must be an array of emails or phone numbers.",
  "data": null
}
```

#### Empty Array
```json
{
  "status": false,
  "message": "The 'identifiers' array cannot be empty. Please provide at least one email or phone number.",
  "data": null
}
```

#### Too Many Identifiers
```json
{
  "status": false,
  "message": "You can check a maximum of 100 identifiers at once. Please reduce the number and try again.",
  "data": null
}
```

#### Invalid Identifiers (Non-string or empty)
```json
{
  "status": false,
  "message": "All identifiers must be non-empty strings (emails or phone numbers).",
  "data": null
}
```

#### Success
```json
{
  "status": true,
  "message": "Found 2 registered user(s) from 3 identifier(s).",
  "data": {
    "registeredUsers": [
      {
        "identifier": "user@example.com",
        "userId": "...",
        "fullName": "..."
      }
    ],
    "totalChecked": 3,
    "totalFound": 2
  }
}
```

---

## Global Error Handling

### Invalid JSON
```json
{
  "status": false,
  "message": "Invalid JSON format in request body. Please check your data and try again.",
  "data": null
}
```

### MongoDB Validation Error
```json
{
  "status": false,
  "message": "Validation failed: email is required, password must be at least 6 characters",
  "data": null
}
```

### MongoDB Duplicate Key
```json
{
  "status": false,
  "message": "This email is already in use. Please use a different email.",
  "data": null
}
```

### Invalid ObjectId
```json
{
  "status": false,
  "message": "Invalid _id: abc123. Please provide a valid identifier.",
  "data": null
}
```

---

## Best Practices Implemented

### ✅ 1. Input Validation
- All required fields are validated before processing
- Email format validation using regex
- Password strength requirements (minimum 6 characters)
- Phone number format validation
- Array type and content validation

### ✅ 2. Security
- Passwords are hashed using bcrypt
- JWT tokens for authentication
- Token expiration handling
- Don't reveal if user exists in forgot password (security best practice)
- OTP expiration (10 minutes)
- Reset token expiration (15 minutes)

### ✅ 3. User Experience
- Clear, actionable error messages
- Specific field-level validation errors
- Success messages that confirm actions
- Helpful suggestions (e.g., "try logging in" when email exists)

### ✅ 4. Error Logging
- All errors are logged to console with context
- Stack traces in development mode only
- Sensitive information excluded from logs

### ✅ 5. Rate Limiting Considerations
- Maximum 100 identifiers per check-registered request
- Prevents abuse and performance issues

### ✅ 6. Database Error Handling
- MongoDB duplicate key errors
- Validation errors
- Cast errors (invalid ObjectId)
- Connection errors

---

## Testing Checklist

- [x] Missing required fields
- [x] Invalid email format
- [x] Short password
- [x] Invalid phone format
- [x] Duplicate email/phone
- [x] Invalid credentials
- [x] Missing authentication token
- [x] Invalid authentication token
- [x] Expired authentication token
- [x] Invalid OTP format
- [x] Expired OTP
- [x] Used OTP
- [x] Invalid reset token
- [x] Expired reset token
- [x] Empty identifiers array
- [x] Non-array identifiers
- [x] Too many identifiers
- [x] Invalid JSON format
- [x] All success scenarios

---

## Frontend Integration Tips

### 1. Display Error Messages Directly
```javascript
try {
  const response = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });
  
  const data = await response.json();
  
  if (!data.status) {
    // Display data.message directly to user
    showError(data.message);
  } else {
    // Success
    showSuccess(data.message);
  }
} catch (error) {
  showError('Network error. Please check your connection.');
}
```

### 2. Handle Token Expiration
```javascript
if (response.status === 401) {
  // Token expired or invalid
  localStorage.removeItem('token');
  redirectToLogin();
}
```

### 3. Field-Level Validation
```javascript
// The API returns specific field errors
// Example: "Missing required fields: fullName, password"
// Parse and highlight specific fields in your form
```

---

## Maintenance Notes

- All error messages are in English
- Messages are user-friendly and non-technical
- Status codes follow REST conventions
- Response format is consistent across all endpoints
- Error logging includes context for debugging
- No breaking changes to existing API contracts
