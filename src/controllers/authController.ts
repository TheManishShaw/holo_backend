import { Request, Response } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import User from "../models/User";
import OTP from "../models/OTP";
import { sendOTPEmail } from "../utils/emailService";
import { sendResponse } from "../utils/responseHandler";

// Generate JWT Token
const generateToken = (id: string) => {
  return jwt.sign({ id }, process.env.JWT_SECRET || "secret", {
    expiresIn: "30d",
  });
};

// @desc    Register new user
// @route   POST /api/auth/register
// @access  Public
export const registerUser = async (
  req: Request,
  res: Response
): Promise<any> => {
  const { fullName, email, password, phone } = req.body;

  try {
    // Validate required fields
    const missingFields = [];
    if (!fullName) missingFields.push("fullName");
    if (!email) missingFields.push("email");
    if (!password) missingFields.push("password");
    if (!phone) missingFields.push("phone");

    if (missingFields.length > 0) {
      return sendResponse(
        res,
        400,
        false,
        `Missing required fields: ${missingFields.join(", ")}. Please provide all required information.`
      );
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return sendResponse(res, 400, false, "Please provide a valid email address.");
    }

    // Validate password strength
    if (password.length < 6) {
      return sendResponse(res, 400, false, "Password must be at least 6 characters long.");
    }

    // Validate phone format (basic check)
    const phoneRegex = /^\+?[1-9]\d{1,14}$/;
    if (!phoneRegex.test(phone.replace(/[\s-]/g, ""))) {
      return sendResponse(res, 400, false, "Please provide a valid phone number.");
    }

    // Check if user exists by email or phone
    const userExists = await User.findOne({ 
      $or: [{ email }, { phoneNumber: phone }] 
    });

    if (userExists) {
      if (userExists.email === email) {
        return sendResponse(res, 409, false, "This email is already registered. Please use a different email or try logging in.");
      }
      if (userExists.phoneNumber === phone) {
        return sendResponse(res, 409, false, "This phone number is already registered. Please use a different number or try logging in.");
      }
      return sendResponse(res, 409, false, "An account with these credentials already exists. Please try logging in.");
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create user
    const user = await User.create({
      fullName,
      email,
      phoneNumber: phone,
      password: hashedPassword,
    });

    if (user) {
      return sendResponse(res, 201, true, "Account created successfully! You are now logged in.", {
        _id: user.id,
        fullName: user.fullName,
        email: user.email,
        phoneNumber: user.phoneNumber,
        token: generateToken(user.id),
      });
    } else {
      return sendResponse(res, 400, false, "Unable to create account. Please check your information and try again.");
    }
  } catch (error: any) {
    console.error("Registration error:", error);
    
    // Handle MongoDB duplicate key errors
    if (error.code === 11000) {
      const field = Object.keys(error.keyPattern)[0];
      return sendResponse(res, 409, false, `This ${field} is already registered. Please use a different ${field}.`);
    }
    
    // Handle validation errors
    if (error.name === "ValidationError") {
      const messages = Object.values(error.errors).map((err: any) => err.message);
      return sendResponse(res, 400, false, `Validation failed: ${messages.join(", ")}`);
    }
    
    return sendResponse(res, 500, false, "An error occurred while creating your account. Please try again later.");
  }
};

// @desc    Authenticate a user
// @route   POST /api/auth/login
// @access  Public
export const loginUser = async (req: Request, res: Response): Promise<any> => {
  const { email, password } = req.body;

  try {
    // Validate required fields
    if (!email || !password) {
      const missing = [];
      if (!email) missing.push("email");
      if (!password) missing.push("password");
      return sendResponse(
        res,
        400,
        false,
        `Please provide ${missing.join(" and ")} to log in.`
      );
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return sendResponse(res, 400, false, "Please provide a valid email address.");
    }

    const user = await User.findOne({ email });

    if (!user) {
      return sendResponse(res, 401, false, "No account found with this email. Please check your email or sign up.");
    }

    const isPasswordValid = await bcrypt.compare(password, user.password || "");
    
    if (!isPasswordValid) {
      return sendResponse(res, 401, false, "Incorrect password. Please try again or reset your password.");
    }

    return sendResponse(res, 200, true, "Login successful! Welcome back.", {
      _id: user.id,
      fullName: user.fullName,
      email: user.email,
      token: generateToken(user.id),
    });
  } catch (error: any) {
    console.error("Login error:", error);
    return sendResponse(res, 500, false, "An error occurred while logging in. Please try again later.");
  }
};

// @desc    Get user data
// @route   GET /api/auth/me
// @access  Private
export const getMe = async (
  req: Request | any,
  res: Response
): Promise<any> => {
  try {
    if (!req.user || !req.user.id) {
      return sendResponse(res, 401, false, "Authentication required. Please log in to access your profile.");
    }

    const user = await User.findById(req.user.id);

    if (!user) {
      return sendResponse(res, 404, false, "User account not found. Your account may have been deleted.");
    }

    return sendResponse(res, 200, true, "Profile retrieved successfully.", {
      id: user._id,
      fullName: user.fullName,
      email: user.email,
      phoneNumber: user.phoneNumber,
    });
  } catch (error: any) {
    console.error("Get user error:", error);
    return sendResponse(res, 500, false, "Unable to retrieve your profile. Please try again later.");
  }
};

// @desc    Request Password Reset (Send OTP)
// @route   POST /api/auth/forgot-password
// @access  Public
export const forgotPassword = async (
  req: Request,
  res: Response
): Promise<any> => {
  const { email } = req.body;

  try {
    // Validate email field
    if (!email) {
      return sendResponse(res, 400, false, "Please provide your email address to reset your password.");
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return sendResponse(res, 400, false, "Please provide a valid email address.");
    }

    const user = await User.findOne({ email });

    if (!user) {
      // For security, don't reveal if user exists
      return sendResponse(res, 200, true, "If an account exists with this email, you will receive a password reset code shortly.");
    }

    // Generate 6-digit OTP
    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();

    // Set expiry to 10 minutes from now
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    // Save OTP to database
    await OTP.create({
      email,
      otp: otpCode,
      expiresAt,
    });

    // Send OTP via email
    const emailSent = await sendOTPEmail(email, otpCode);

    if (emailSent) {
      return sendResponse(res, 200, true, "A 6-digit verification code has been sent to your email. Please check your inbox and enter the code to reset your password.");
    } else {
      return sendResponse(res, 500, false, "Unable to send verification code. Please check your email address and try again.");
    }
  } catch (error: any) {
    console.error("Forgot password error:", error);
    return sendResponse(res, 500, false, "An error occurred while processing your request. Please try again later.");
  }
};

// @desc    Verify OTP
// @route   POST /api/auth/verify-otp
// @access  Public
export const verifyOTP = async (req: Request, res: Response): Promise<any> => {
  const { email, otp } = req.body;

  try {
    // Validate required fields
    if (!email || !otp) {
      const missing = [];
      if (!email) missing.push("email");
      if (!otp) missing.push("verification code");
      return sendResponse(
        res,
        400,
        false,
        `Please provide ${missing.join(" and ")} to verify.`
      );
    }

    // Validate OTP format (6 digits)
    if (!/^\d{6}$/.test(otp)) {
      return sendResponse(res, 400, false, "Verification code must be a 6-digit number.");
    }

    const otpRecord = await OTP.findOne({
      email,
      otp,
      isUsed: false,
      expiresAt: { $gt: new Date() },
    });

    if (!otpRecord) {
      // Check if OTP exists but is expired or used
      const expiredOTP = await OTP.findOne({ email, otp });
      
      if (expiredOTP) {
        if (expiredOTP.isUsed) {
          return sendResponse(res, 400, false, "This verification code has already been used. Please request a new code.");
        }
        if (expiredOTP.expiresAt < new Date()) {
          return sendResponse(res, 400, false, "This verification code has expired. Please request a new code.");
        }
      }
      
      return sendResponse(res, 400, false, "Invalid verification code. Please check the code and try again.");
    }

    // Mark OTP as used
    otpRecord.isUsed = true;
    await otpRecord.save();

    // Generate a temporary reset token (valid for 15 minutes)
    const resetToken = jwt.sign(
      { email, purpose: "password_reset" },
      process.env.JWT_SECRET || "secret",
      { expiresIn: "15m" }
    );

    return sendResponse(res, 200, true, "Verification successful! You can now reset your password.", {
      resetToken,
    });
  } catch (error: any) {
    console.error("Verify OTP error:", error);
    return sendResponse(res, 500, false, "An error occurred while verifying your code. Please try again.");
  }
};

// @desc    Reset Password
// @route   POST /api/auth/reset-password
// @access  Public
export const resetPassword = async (
  req: Request,
  res: Response
): Promise<any> => {
  const { resetToken, newPassword } = req.body;

  try {
    // Validate required fields
    if (!resetToken || !newPassword) {
      const missing = [];
      if (!resetToken) missing.push("reset token");
      if (!newPassword) missing.push("new password");
      return sendResponse(
        res,
        400,
        false,
        `Please provide ${missing.join(" and ")} to reset your password.`
      );
    }

    // Validate password strength
    if (newPassword.length < 6) {
      return sendResponse(res, 400, false, "New password must be at least 6 characters long.");
    }

    // Verify reset token
    let decoded: any;
    try {
      decoded = jwt.verify(
        resetToken,
        process.env.JWT_SECRET || "secret"
      ) as any;
    } catch (jwtError: any) {
      if (jwtError.name === "TokenExpiredError") {
        return sendResponse(res, 400, false, "Your password reset session has expired. Please request a new verification code.");
      }
      if (jwtError.name === "JsonWebTokenError") {
        return sendResponse(res, 400, false, "Invalid reset token. Please request a new verification code.");
      }
      throw jwtError;
    }

    if (!decoded || decoded.purpose !== "password_reset") {
      return sendResponse(res, 400, false, "Invalid reset token. Please request a new verification code.");
    }

    const email = decoded.email;
    const user = await User.findOne({ email });

    if (!user) {
      return sendResponse(res, 404, false, "Account not found. Please contact support if you need assistance.");
    }

    // Hash new password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    // Update user password
    user.password = hashedPassword;
    await user.save();

    // Invalidate any remaining OTPs for this email
    await OTP.updateMany({ email }, { isUsed: true });

    return sendResponse(res, 200, true, "Password reset successfully! You can now log in with your new password.");
  } catch (error: any) {
    console.error("Reset password error:", error);
    return sendResponse(res, 500, false, "An error occurred while resetting your password. Please try again later.");
  }
};

// @desc    Check if contacts are registered users
// @route   POST /api/users/check-registered
// @access  Private
export const checkRegisteredUsers = async (
  req: Request | any,
  res: Response
): Promise<any> => {
  const { identifiers } = req.body;

  try {
    // Validate identifiers field
    if (!identifiers) {
      return sendResponse(res, 400, false, "Please provide an 'identifiers' array containing emails or phone numbers to check.");
    }

    if (!Array.isArray(identifiers)) {
      return sendResponse(res, 400, false, "The 'identifiers' field must be an array of emails or phone numbers.");
    }

    if (identifiers.length === 0) {
      return sendResponse(res, 400, false, "The 'identifiers' array cannot be empty. Please provide at least one email or phone number.");
    }

    // Limit array size to prevent abuse
    if (identifiers.length > 100) {
      return sendResponse(res, 400, false, "You can check a maximum of 100 identifiers at once. Please reduce the number and try again.");
    }

    // Validate that identifiers are strings
    const invalidIdentifiers = identifiers.filter(id => typeof id !== 'string' || id.trim() === '');
    if (invalidIdentifiers.length > 0) {
      return sendResponse(res, 400, false, "All identifiers must be non-empty strings (emails or phone numbers).");
    }

    // Find users by email OR phone number
    const users = await User.find({
      $or: [
        { email: { $in: identifiers } },
        { phoneNumber: { $in: identifiers } }
      ]
    }).select('_id email phoneNumber fullName');

    // Create a map of registered identifiers to user info
    const registeredUsers = users.flatMap(user => {
      const matches = [];
      
      // Add match for email if it's in the identifiers list
      if (user.email && identifiers.includes(user.email)) {
        matches.push({
          identifier: user.email,
          userId: user._id,
          fullName: user.fullName
        });
      }
      
      // Add match for phone if it's in the identifiers list
      if (user.phoneNumber && identifiers.includes(user.phoneNumber)) {
        matches.push({
          identifier: user.phoneNumber,
          userId: user._id,
          fullName: user.fullName
        });
      }
      
      return matches;
    });

    return sendResponse(res, 200, true, `Found ${registeredUsers.length} registered user(s) from ${identifiers.length} identifier(s).`, {
      registeredUsers,
      totalChecked: identifiers.length,
      totalFound: registeredUsers.length
    });
  } catch (error: any) {
    console.error("Check registered users error:", error);
    return sendResponse(res, 500, false, "An error occurred while checking registered users. Please try again later.");
  }
};

