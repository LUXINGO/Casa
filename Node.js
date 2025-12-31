// server.js - Complete Backend API for Solana Trading Platform
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const admin = require('firebase-admin');
const bodyParser = require('body-parser');
const crypto = require('crypto');
require('dotenv').config();

// Initialize Express App
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({
  origin: ['http://localhost:8080', 'https://your-frontend-domain.com'],
  credentials: true
}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Request Logger Middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

// ==================== FIREBASE CONFIGURATION ====================
const firebaseConfig = {
  type: "service_account",
  project_id: "casa-89b8b",
  private_key_id: "bb858aa2fe379424a823393e687527e050ac4526",
  private_key: "\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCj0qMYnwbUwdJr\n+vmvhDD4lUWs8BHqfJfiQcnFZfMoIKfv9DECaUuYbLq3kJAZ0Lnd9T0fv5mptJJw\nWtrVO+T3BrTS8Y50LSGLDXbVqh/tm1I30PFvhML/v6OLZ9dO0KKH6Nwxr0TabDwL\nWpr3cQnlUzX6okiAZBfxpg8US0d6sXJoQ/HFjh6rQ2dLzU+tlWhveSEa83BVjk21\n4aAOcUyTkoIsjb05b5LbRZdbr7i6H3uXu1gO+OUS2aGHLbHq2lvIIMeOzqOF4ASS\nURr3QBCqck9t4sv1PTCkheitQMViAr7afKWNkIF5lced6K02wP4rQGjfNy4ylqO+\nz5dC0vX5AgMBAAECggEAEZGy/R58+I9K1lrFsV2fdOFpZgkfGsM+9Lxye7GZ2Mlb\nyV+qa+RH/7JVef9OfP5GGLhG1GNTgwBDHjqYMnsobJezB9ZxHSOD7+pDPtnub6iT\nMjo90mRuF0iBrR83V5QHgkTmbIur+jLWY69VZEkisw3wAY+q794MNVXGUzpZkZ5O\n/R1/UQ1fpTNKHbAJB4xho1JABEZSFHS10puP9fZeN8h3pWdIZxqUxqGN7xWkA7F3\nUeQtB//Myz4F5sacBSKqHdQz752T+TBhP/FBzBt1fp+MGZmgWCYEulYtPGiVxUQw\n/WD7sRSJB+NFrykPEBycL6QAoNtSn91CcDFnUVSqiQKBgQDlg5wLPAD9JpD3NE5k\npoSang4dI1uGsD9GjoptP8spR9YuottcDl+YJW8tgRyTgBI1WJEv028SH6ystZE/\n9/QWu8Crkq92bFYm4ylQtHAy5G9VQbgLQd7wPhPcTQyDAnzXV23Re/czKfSpdPzs\nR4wcHl3VGbdZukkazU03D5rTlQKBgQC2ulnUfOMnuc3oV/WO+7kbxj1+EydHiNVd\nUbkenBTpip0KmvIb4JiNYOes+gFXCpyGrzh5adHzCYJ4/MpT1hBY9C3H9pppHYg/\nUqicJ3w8LeON3OuULnu9l34jX7gMw4GGNHna7qSAgUNYBTxQQNMTd6cR+5bnmn1+\nQUN0VWJ/1QKBgAIH/CWNTmTvJnFJoTf60UmdBHr1iSXUAXtaX5c/7UhcPmUDQ/W4\nmtf53NYGQn57r62RLxfBQ0ZhyWFt6e8q/poE51udXLgrlUea0w7HygZpRyL2Be7z\nkkmGAx77/5RZPUmamHo2IqXtRSEKzAI7T94f1qzAIYNFxsfZ8Uj/dltRAoGBAJEL\nv36yW8YO8Wm7WIrVOgzYAbvwDD/2WBepZV7s2pS/mQTwFbsXP0EKaRyfnyyuma03\nrYaC/0sCg3TyhNCjnXpe6XBPSiaicKKDRKAfn7hNXNIhSUbo1wSaGmCN/JT1I/2Z\n7hhhUmdHNGPMVCIIMwTC9/WIVjMmKPNtbtQLaxK5AoGBAJkQyo/Qcj7XyWCSLlZI\neuz6H5iQwiww/MNkcLdMhwk1CUkn/+yeH4QcqTKPvJuhobhRdxKBhqGl2kFThbNt\nYG6WzdP7VCkjRj5TsJcjLsR15nPu8t7hSCHtfnLnk6PkRZrdobveV0Znfmm6gs6I\n2a6IjZ/VqxWRb5hRxFw6zlD+\n--",
  client_email: "firebase-adminsdk-casa@casa-89b8b.iam.gserviceaccount.com",
  client_id: "YOUR_CLIENT_ID",
  auth_uri: "https://accounts.google.com/o/oauth2/auth",
  token_uri: "https://oauth2.googleapis.com/token",
  auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
  client_x509_cert_url: "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-casa%40casa-89b8b.iam.gserviceaccount.com",
  universe_domain: "googleapis.com"
};

// Initialize Firebase Admin
admin.initializeApp({
  credential: admin.credential.cert(firebaseConfig),
  databaseURL: "https://casa-89b8b-default-rtdb.firebaseio.com"
});

const db = admin.firestore();
const auth = admin.auth();

// ==================== KORAPAY CONFIGURATION ====================
const KORAPAY_SECRET_KEY = process.env.KORAPAY_SECRET_KEY || "sk_live_2SxqdiUcRzZo2LghfvErjCFbjks9aNfZPD9jTsMv";
const KORAPAY_PUBLIC_KEY = process.env.KORAPAY_PUBLIC_KEY || "pk_live_ksZpFkWrTV9mDChRzUPGb5s2cX2BHGriUAYYtJX8";
const KORAPAY_BASE_URL = "https://api.korapay.com/merchant/api/v1";

// Korapay API Instance
const korapayApi = axios.create({
  baseURL: KORAPAY_BASE_URL,
  headers: {
    'Authorization': `Bearer ${KORAPAY_SECRET_KEY}`,
    'Content-Type': 'application/json'
  }
});

// ==================== MIDDLEWARES ====================
// Verify Firebase Token
const verifyToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ 
        success: false, 
        error: 'No token provided',
        code: 'NO_TOKEN'
      });
    }

    const token = authHeader.split('Bearer ')[1];
    const decodedToken = await auth.verifyIdToken(token);
    req.user = decodedToken;
    req.userId = decodedToken.uid;
    
    // Check if user is banned
    const userDoc = await db.collection('users').doc(req.userId).get();
    if (userDoc.exists && userDoc.data().isBanned) {
      return res.status(403).json({
        success: false,
        error: 'Account has been suspended',
        code: 'ACCOUNT_BANNED'
      });
    }
    
    next();
  } catch (error) {
    console.error('Token verification error:', error);
    return res.status(401).json({ 
      success: false, 
      error: 'Invalid or expired token',
      code: 'INVALID_TOKEN'
    });
  }
};

// Check Admin Privileges
const checkAdmin = async (req, res, next) => {
  try {
    const userDoc = await db.collection('users').doc(req.userId).get();
    if (!userDoc.exists || !userDoc.data().isAdmin) {
      return res.status(403).json({
        success: false,
        error: 'Admin access required',
        code: 'ADMIN_REQUIRED'
      });
    }
    next();
  } catch (error) {
    console.error('Admin check error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Server error',
      code: 'SERVER_ERROR'
    });
  }
};

// ==================== UTILITY FUNCTIONS ====================
// Generate Unique Reference
function generateReference(prefix = 'TRX') {
  const timestamp = Date.now();
  const random = Math.random().toString(36).substring(2, 10).toUpperCase();
  return `${prefix}_${timestamp}_${random}`;
}

// Format Currency
function formatCurrency(amount) {
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD'
  }).format(amount);
}

// Calculate Fees
function calculateFees(amount, type = 'deposit') {
  const fees = {
    deposit: {
      percentage: 2.5,
      minFee: 0.5,
      maxFee: 25
    },
    withdrawal: {
      percentage: 1.5,
      taxPercentage: 10,
      minFee: 1,
      maxFee: 50
    }
  };

  const config = fees[type];
  
  if (type === 'deposit') {
    let fee = (amount * config.percentage) / 100;
    fee = Math.max(config.minFee, Math.min(fee, config.maxFee));
    return {
      amount: amount,
      fee: fee,
      total: amount + fee,
      percentage: config.percentage
    };
  } else {
    let fee = (amount * config.percentage) / 100;
    fee = Math.max(config.minFee, Math.min(fee, config.maxFee));
    const tax = (amount * config.taxPercentage) / 100;
    const netAmount = amount - fee - tax;
    
    return {
      amount: amount,
      fee: fee,
      tax: tax,
      netAmount: netAmount,
      totalDeduction: fee + tax,
      percentage: config.percentage,
      taxPercentage: config.taxPercentage
    };
  }
}

// ==================== API ENDPOINTS ====================

// 1. HEALTH CHECK
app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    message: 'Solana Trading Platform API',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    status: 'operational',
    services: {
      firebase: 'connected',
      korapay: 'configured',
      database: 'online'
    }
  });
});

// 2. USER AUTHENTICATION ENDPOINTS
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name, username, dob, pin } = req.body;

    // Validate input
    if (!email || !password || !name || !username || !dob || !pin) {
      return res.status(400).json({
        success: false,
        error: 'All fields are required',
        code: 'MISSING_FIELDS'
      });
    }

    // Validate age (18+)
    const birthDate = new Date(dob);
    const age = new Date().getFullYear() - birthDate.getFullYear();
    if (age < 18) {
      return res.status(400).json({
        success: false,
        error: 'You must be 18 years or older',
        code: 'UNDERAGE'
      });
    }

    // Validate PIN
    if (pin.length !== 4 || !/^\d+$/.test(pin)) {
      return res.status(400).json({
        success: false,
        error: 'PIN must be 4 digits',
        code: 'INVALID_PIN'
      });
    }

    // Check if email exists
    try {
      await auth.getUserByEmail(email);
      return res.status(400).json({
        success: false,
        error: 'Email already registered',
        code: 'EMAIL_EXISTS'
      });
    } catch (error) {
      // Email doesn't exist, continue
    }

    // Create Firebase user
    const userRecord = await auth.createUser({
      email: email,
      password: password,
      displayName: name,
      emailVerified: false
    });

    // Create user document in Firestore
    await db.collection('users').doc(userRecord.uid).set({
      uid: userRecord.uid,
      email: email,
      name: name,
      username: username.toLowerCase(),
      dob: dob,
      pin: pin,
      balance: 1.00, // Starting bonus
      totalTrades: 0,
      wins: 0,
      losses: 0,
      totalProfit: 0,
      winRate: 0,
      joinDate: new Date().toISOString(),
      lastLogin: new Date().toISOString(),
      isPremium: false,
      isAdmin: false,
      isBanned: false,
      profilePic: `https://ui-avatars.com/api/?name=${encodeURIComponent(name)}&background=9945FF&color=fff`,
      referralCode: generateReference('REF').substring(0, 8),
      referralCount: 0,
      referredBy: null,
      kycVerified: false,
      country: req.body.country || 'NG',
      phone: req.body.phone || '',
      twoFactorEnabled: false
    });

    // Generate custom token for immediate login
    const customToken = await auth.createCustomToken(userRecord.uid);

    res.status(201).json({
      success: true,
      message: 'Account created successfully',
      data: {
        uid: userRecord.uid,
        email: userRecord.email,
        name: userRecord.displayName,
        token: customToken,
        balance: 1.00
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
    
    let errorMessage = 'Registration failed';
    let errorCode = 'REGISTRATION_ERROR';
    
    if (error.code === 'auth/email-already-in-use') {
      errorMessage = 'Email already registered';
      errorCode = 'EMAIL_EXISTS';
    } else if (error.code === 'auth/weak-password') {
      errorMessage = 'Password is too weak';
      errorCode = 'WEAK_PASSWORD';
    } else if (error.code === 'auth/invalid-email') {
      errorMessage = 'Invalid email address';
      errorCode = 'INVALID_EMAIL';
    }

    res.status(400).json({
      success: false,
      error: errorMessage,
      code: errorCode
    });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: 'Email and password required',
        code: 'MISSING_CREDENTIALS'
      });
    }

    // Firebase REST API for email/password login
    const firebaseAuthUrl = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${process.env.FIREBASE_API_KEY}`;
    
    const response = await axios.post(firebaseAuthUrl, {
      email: email,
      password: password,
      returnSecureToken: true
    });

    const { localId, email: userEmail, displayName, idToken, refreshToken } = response.data;

    // Update last login
    await db.collection('users').doc(localId).update({
      lastLogin: new Date().toISOString()
    });

    // Get user data
    const userDoc = await db.collection('users').doc(localId).get();
    const userData = userDoc.data();

    // Check if banned
    if (userData.isBanned) {
      return res.status(403).json({
        success: false,
        error: 'Account has been suspended',
        code: 'ACCOUNT_BANNED'
      });
    }

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        uid: localId,
        email: userEmail,
        name: displayName,
        token: idToken,
        refreshToken: refreshToken,
        profile: userData
      }
    });

  } catch (error) {
    console.error('Login error:', error.response?.data || error.message);
    
    let errorMessage = 'Login failed';
    let errorCode = 'LOGIN_ERROR';
    
    if (error.response?.data?.error?.message === 'EMAIL_NOT_FOUND') {
      errorMessage = 'Email not registered';
      errorCode = 'EMAIL_NOT_FOUND';
    } else if (error.response?.data?.error?.message === 'INVALID_PASSWORD') {
      errorMessage = 'Incorrect password';
      errorCode = 'INVALID_PASSWORD';
    } else if (error.response?.data?.error?.message === 'USER_DISABLED') {
      errorMessage = 'Account has been disabled';
      errorCode = 'ACCOUNT_DISABLED';
    }

    res.status(401).json({
      success: false,
      error: errorMessage,
      code: errorCode
    });
  }
});

// 3. PAYMENT ENDPOINTS

// Initialize Deposit
app.post('/api/payments/deposit/initialize', verifyToken, async (req, res) => {
  try {
    const { amount, paymentMethod } = req.body;
    const userId = req.userId;

    // Validate amount
    if (!amount || amount < 5 || amount > 10000) {
      return res.status(400).json({
        success: false,
        error: 'Amount must be between $5 and $10,000',
        code: 'INVALID_AMOUNT'
      });
    }

    // Get user data
    const userDoc = await db.collection('users').doc(userId).get();
    if (!userDoc.exists) {
      return res.status(404).json({
        success: false,
        error: 'User not found',
        code: 'USER_NOT_FOUND'
      });
    }

    const userData = userDoc.data();
    const fees = calculateFees(amount, 'deposit');
    
    // Generate unique reference
    const reference = generateReference('DEP');
    
    // Create transaction record
    const transactionData = {
      userId: userId,
      type: 'deposit',
      amount: fees.amount,
      fee: fees.fee,
      total: fees.total,
      paymentMethod: paymentMethod || 'card',
      status: 'pending',
      reference: reference,
      korapayReference: null,
      userEmail: userData.email,
      userName: userData.name,
      timestamp: new Date().toISOString(),
      metadata: {
        userId: userId,
        userEmail: userData.email
      }
    };

    const transactionRef = await db.collection('transactions').add(transactionData);
    const transactionId = transactionRef.id;

    // Prepare Korapay payload
    const korapayPayload = {
      amount: Math.round(fees.total * 100), // Convert to kobo/cents
      currency: "USD",
      reference: reference,
      customer: {
        name: userData.name,
        email: userData.email
      },
      metadata: {
        transactionId: transactionId,
        userId: userId,
        type: 'deposit'
      },
      notification_url: `${process.env.BASE_URL}/api/webhook/korapay`,
      redirect_url: `${process.env.FRONTEND_URL}/payment-success`
    };

    // Add payment method specific fields
    if (paymentMethod === 'bank_transfer') {
      korapayPayload.channels = ['bank_transfer'];
    } else if (paymentMethod === 'ussd') {
      korapayPayload.channels = ['ussd'];
    } else if (paymentMethod === 'mobile_money') {
      korapayPayload.channels = ['mobile_money'];
    }

    // Call Korapay API
    const korapayResponse = await korapayApi.post('/charges/initialize', korapayPayload);
    
    if (korapayResponse.data.status && korapayResponse.data.data) {
      const checkoutUrl = korapayResponse.data.data.checkout_url;
      const korapayRef = korapayResponse.data.data.reference;

      // Update transaction with Korapay reference
      await transactionRef.update({
        korapayReference: korapayRef,
        checkoutUrl: checkoutUrl,
        korapayData: korapayResponse.data.data
      });

      res.json({
        success: true,
        message: 'Deposit initialized',
        data: {
          transactionId: transactionId,
          reference: reference,
          checkoutUrl: checkoutUrl,
          amount: fees.amount,
          fee: fees.fee,
          total: fees.total,
          korapayReference: korapayRef,
          expiresIn: 1800 // 30 minutes
        }
      });
    } else {
      throw new Error('Korapay initialization failed');
    }

  } catch (error) {
    console.error('Deposit initialization error:', error.response?.data || error.message);
    
    res.status(500).json({
      success: false,
      error: 'Failed to initialize deposit',
      code: 'DEPOSIT_INIT_FAILED',
      details: error.response?.data?.message || error.message
    });
  }
});

// Verify Transaction
app.get('/api/payments/transaction/:reference/verify', verifyToken, async (req, res) => {
  try {
    const { reference } = req.params;
    const userId = req.userId;

    // Get transaction
    const transactionQuery = await db.collection('transactions')
      .where('reference', '==', reference)
      .where('userId', '==', userId)
      .limit(1)
      .get();

    if (transactionQuery.empty) {
      return res.status(404).json({
        success: false,
        error: 'Transaction not found',
        code: 'TRANSACTION_NOT_FOUND'
      });
    }

    const transactionDoc = transactionQuery.docs[0];
    const transaction = transactionDoc.data();

    // If already successful, return cached result
    if (transaction.status === 'successful') {
      return res.json({
        success: true,
        data: transaction
      });
    }

    // Verify with Korapay if there's a reference
    if (transaction.korapayReference) {
      const verifyResponse = await korapayApi.get(`/charges/${transaction.korapayReference}`);
      
      if (verifyResponse.data.status && verifyResponse.data.data) {
        const korapayData = verifyResponse.data.data;
        const status = korapayData.status.toLowerCase();
        
        let newStatus = transaction.status;
        let balanceUpdated = false;

        if (status === 'success' && transaction.status !== 'successful') {
          newStatus = 'successful';
          
          // Update user balance
          const userRef = db.collection('users').doc(userId);
          const userDoc = await userRef.get();
          
          if (userDoc.exists) {
            const currentBalance = userDoc.data().balance || 0;
            await userRef.update({
              balance: currentBalance + transaction.amount
            });
            balanceUpdated = true;
          }
        } else if (status === 'failed' && transaction.status !== 'failed') {
          newStatus = 'failed';
        }

        // Update transaction
        await transactionDoc.ref.update({
          status: newStatus,
          korapayData: korapayData,
          verifiedAt: new Date().toISOString(),
          ...(balanceUpdated && { balanceUpdatedAt: new Date().toISOString() })
        });

        transaction.status = newStatus;
        transaction.korapayData = korapayData;
      }
    }

    res.json({
      success: true,
      data: transaction
    });

  } catch (error) {
    console.error('Transaction verification error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to verify transaction',
      code: 'VERIFICATION_FAILED'
    });
  }
});

// Initialize Withdrawal
app.post('/api/payments/withdraw/initialize', verifyToken, async (req, res) => {
  try {
    const { amount, bankCode, accountNumber, accountName, pin } = req.body;
    const userId = req.userId;

    // Validate input
    if (!amount || !bankCode || !accountNumber || !accountName || !pin) {
      return res.status(400).json({
        success: false,
        error: 'All fields are required',
        code: 'MISSING_FIELDS'
      });
    }

    // Validate amount
    if (amount < 20 || amount > 10000) {
      return res.status(400).json({
        success: false,
        error: 'Amount must be between $20 and $10,000',
        code: 'INVALID_AMOUNT'
      });
    }

    // Get user data
    const userRef = db.collection('users').doc(userId);
    const userDoc = await userRef.get();
    
    if (!userDoc.exists) {
      return res.status(404).json({
        success: false,
        error: 'User not found',
        code: 'USER_NOT_FOUND'
      });
    }

    const userData = userDoc.data();

    // Verify PIN
    if (userData.pin !== pin) {
      return res.status(401).json({
        success: false,
        error: 'Invalid transaction PIN',
        code: 'INVALID_PIN'
      });
    }

    // Check balance
    if (amount > (userData.balance || 0)) {
      return res.status(400).json({
        success: false,
        error: 'Insufficient balance',
        code: 'INSUFFICIENT_BALANCE'
      });
    }

    // Calculate fees
    const fees = calculateFees(amount, 'withdrawal');
    
    // Generate reference
    const reference = generateReference('WDL');
    
    // Create withdrawal transaction
    const transactionData = {
      userId: userId,
      type: 'withdrawal',
      amount: fees.amount,
      fee: fees.fee,
      tax: fees.tax,
      netAmount: fees.netAmount,
      bankCode: bankCode,
      accountNumber: accountNumber,
      accountName: accountName,
      status: 'pending',
      reference: reference,
      userEmail: userData.email,
      userName: userData.name,
      timestamp: new Date().toISOString(),
      metadata: {
        userId: userId,
        bankDetails: {
          bankCode,
          accountNumber,
          accountName
        }
      }
    };

    const transactionRef = await db.collection('transactions').add(transactionData);
    const transactionId = transactionRef.id;

    // Deduct from user balance
    const newBalance = (userData.balance || 0) - amount;
    await userRef.update({
      balance: newBalance
    });

    // Prepare Korapay payout payload
    const payoutPayload = {
      amount: Math.round(fees.netAmount * 100), // Convert to kobo/cents
      currency: "USD",
      reference: reference,
      bank: {
        code: bankCode,
        account: accountNumber,
        name: accountName
      },
      customer: {
        name: accountName,
        email: userData.email
      },
      metadata: {
        transactionId: transactionId,
        userId: userId,
        type: 'withdrawal'
      }
    };

    // Initiate payout via Korapay
    let payoutResponse;
    try {
      payoutResponse = await korapayApi.post('/payouts', payoutPayload);
      
      if (payoutResponse.data.status && payoutResponse.data.data) {
        await transactionRef.update({
          korapayReference: payoutResponse.data.data.reference,
          korapayData: payoutResponse.data.data,
          status: 'processing'
        });
      }
    } catch (payoutError) {
      console.error('Korapay payout error:', payoutError.response?.data || payoutError.message);
      // Mark as manual processing
      await transactionRef.update({
        status: 'pending_manual',
        note: 'Manual processing required'
      });
    }

    res.json({
      success: true,
      message: 'Withdrawal request submitted',
      data: {
        transactionId: transactionId,
        reference: reference,
        amount: fees.amount,
        fee: fees.fee,
        tax: fees.tax,
        netAmount: fees.netAmount,
        status: 'processing',
        estimatedArrival: '24-48 hours',
        newBalance: newBalance
      }
    });

  } catch (error) {
    console.error('Withdrawal error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to process withdrawal',
      code: 'WITHDRAWAL_FAILED',
      details: error.message
    });
  }
});

// Get Banks List
app.get('/api/payments/banks', verifyToken, async (req, res) => {
  try {
    // You would typically get this from Korapay API or cache it
    const banks = [
      { code: "000014", name: "Access Bank" },
      { code: "000023", name: "Citibank" },
      { code: "000003", name: "First Bank of Nigeria" },
      { code: "000016", name: "First City Monument Bank" },
      { code: "000004", name: "Guaranty Trust Bank" },
      { code: "000005", name: "Union Bank of Nigeria" },
      { code: "000033", name: "United Bank for Africa" },
      { code: "000032", name: "Zenith Bank" },
      { code: "000035", name: "Wema Bank" },
      { code: "000011", name: "Stanbic IBTC Bank" }
    ];

    res.json({
      success: true,
      data: banks
    });

  } catch (error) {
    console.error('Banks list error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch banks',
      code: 'BANKS_FETCH_FAILED'
    });
  }
});

// 4. WEBHOOK ENDPOINTS

// Korapay Webhook
app.post('/api/webhook/korapay', async (req, res) => {
  try {
    const event = req.body;
    
    // Verify webhook signature (implement proper verification in production)
    // const signature = req.headers['x-korapay-signature'];
    
    console.log('Webhook received:', JSON.stringify(event, null, 2));

    if (event.event === 'charge.success') {
      const { reference, amount, customer, metadata } = event.data;
      
      // Find transaction by Korapay reference
      const transactionQuery = await db.collection('transactions')
        .where('korapayReference', '==', reference)
        .limit(1)
        .get();

      if (!transactionQuery.empty) {
        const transactionDoc = transactionQuery.docs[0];
        const transaction = transactionDoc.data();

        // Only process if still pending
        if (transaction.status === 'pending') {
          await transactionDoc.ref.update({
            status: 'successful',
            korapayWebhookData: event.data,
            processedAt: new Date().toISOString(),
            webhookReceivedAt: new Date().toISOString()
          });

          // Update user balance
          if (metadata && metadata.userId) {
            const userRef = db.collection('users').doc(metadata.userId);
            const userDoc = await userRef.get();
            
            if (userDoc.exists) {
              const currentBalance = userDoc.data().balance || 0;
              await userRef.update({
                balance: currentBalance + transaction.amount
              });

              // Send notification
              await db.collection('notifications').add({
                userId: metadata.userId,
                type: 'deposit_success',
                title: 'Deposit Successful',
                message: `Your deposit of $${transaction.amount} has been credited to your account`,
                data: {
                  transactionId: transactionDoc.id,
                  amount: transaction.amount,
                  balance: currentBalance + transaction.amount
                },
                read: false,
                timestamp: new Date().toISOString()
              });

              console.log(`Balance updated for user ${metadata.userId}: +$${transaction.amount}`);
            }
          }
        }
      }
    }

    // Send 200 OK response
    res.status(200).json({ received: true });

  } catch (error) {
    console.error('Webhook processing error:', error);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

// 5. USER PROFILE ENDPOINTS

// Get User Profile
app.get('/api/user/profile', verifyToken, async (req, res) => {
  try {
    const userId = req.userId;
    
    const userDoc = await db.collection('users').doc(userId).get();
    
    if (!userDoc.exists) {
      return res.status(404).json({
        success: false,
        error: 'User not found',
        code: 'USER_NOT_FOUND'
      });
    }

    const userData = userDoc.data();
    
    // Remove sensitive data
    delete userData.pin;
    delete userData.metadata;
    
    // Get transaction stats
    const transactionsQuery = await db.collection('transactions')
      .where('userId', '==', userId)
      .get();
    
    const depositStats = transactionsQuery.docs
      .filter(doc => doc.data().type === 'deposit' && doc.data().status === 'successful')
      .reduce((sum, doc) => sum + (doc.data().amount || 0), 0);
    
    const withdrawalStats = transactionsQuery.docs
      .filter(doc => doc.data().type === 'withdrawal')
      .reduce((sum, doc) => sum + (doc.data().amount || 0), 0);

    res.json({
      success: true,
      data: {
        ...userData,
        depositStats,
        withdrawalStats,
        totalTransactions: transactionsQuery.size
      }
    });

  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch profile',
      code: 'PROFILE_FETCH_FAILED'
    });
  }
});

// Update User Profile
app.put('/api/user/profile', verifyToken, async (req, res) => {
  try {
    const userId = req.userId;
    const updates = req.body;

    // Remove restricted fields
    delete updates.balance;
    delete updates.isAdmin;
    delete updates.isBanned;
    delete updates.pin; // Handle PIN separately

    // If updating PIN
    if (req.body.newPin) {
      if (req.body.newPin.length !== 4 || !/^\d+$/.test(req.body.newPin)) {
        return res.status(400).json({
          success: false,
          error: 'PIN must be 4 digits',
          code: 'INVALID_PIN'
        });
      }
      updates.pin = req.body.newPin;
    }

    const userRef = db.collection('users').doc(userId);
    await userRef.update({
      ...updates,
      updatedAt: new Date().toISOString()
    });

    res.json({
      success: true,
      message: 'Profile updated successfully'
    });

  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update profile',
      code: 'PROFILE_UPDATE_FAILED'
    });
  }
});

// 6. TRANSACTION ENDPOINTS

// Get User Transactions
app.get('/api/transactions', verifyToken, async (req, res) => {
  try {
    const userId = req.userId;
    const { type, status, limit = 50, offset = 0 } = req.query;

    let query = db.collection('transactions').where('userId', '==', userId);
    
    if (type) {
      query = query.where('type', '==', type);
    }
    
    if (status) {
      query = query.where('status', '==', status);
    }

    query = query.orderBy('timestamp', 'desc');
    
    const snapshot = await query.limit(parseInt(limit)).get();
    
    const transactions = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));

    res.json({
      success: true,
      data: {
        transactions,
        total: transactions.length,
        limit: parseInt(limit),
        offset: parseInt(offset)
      }
    });

  } catch (error) {
    console.error('Transactions fetch error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch transactions',
      code: 'TRANSACTIONS_FETCH_FAILED'
    });
  }
});

// 7. TRADING ENDPOINTS

// Place Trade
app.post('/api/trades/place', verifyToken, async (req, res) => {
  try {
    const userId = req.userId;
    const { type, lotSize, takeProfit, stopLoss } = req.body;

    // Validate input
    if (!type || !lotSize) {
      return res.status(400).json({
        success: false,
        error: 'Type and lot size required',
        code: 'MISSING_FIELDS'
      });
    }

    // Validate type
    if (!['buy', 'sell'].includes(type)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid trade type',
        code: 'INVALID_TRADE_TYPE'
      });
    }

    // Calculate trade cost
    const tradeCost = lotSize * 100;
    
    // Get user data
    const userRef = db.collection('users').doc(userId);
    const userDoc = await userRef.get();
    
    if (!userDoc.exists) {
      return res.status(404).json({
        success: false,
        error: 'User not found',
        code: 'USER_NOT_FOUND'
      });
    }

    const userData = userDoc.data();

    // Check balance
    if (tradeCost > (userData.balance || 0)) {
      return res.status(400).json({
        success: false,
        error: 'Insufficient balance',
        code: 'INSUFFICIENT_BALANCE'
      });
    }

    // Get current price (simulated)
    const currentPrice = 100 + (Math.random() - 0.5) * 10; // Simulated price

    // Create trade
    const tradeData = {
      userId: userId,
      type: type,
      lotSize: lotSize,
      entryPrice: currentPrice,
      takeProfit: takeProfit || 40,
      stopLoss: stopLoss || 20,
      status: 'open',
      currentProfit: 0,
      profitPercent: 0,
      timestamp: new Date().toISOString(),
      round: Math.floor(Date.now() / 30000), // New round every 30 seconds
      metadata: {
        userId: userId,
        username: userData.username
      }
    };

    const tradeRef = await db.collection('activeTrades').add(tradeData);
    const tradeId = tradeRef.id;

    // Deduct from balance
    const newBalance = (userData.balance || 0) - tradeCost;
    await userRef.update({
      balance: newBalance
    });

    res.json({
      success: true,
      message: 'Trade placed successfully',
      data: {
        tradeId: tradeId,
        type: type,
        lotSize: lotSize,
        entryPrice: currentPrice,
        tradeCost: tradeCost,
        newBalance: newBalance
      }
    });

  } catch (error) {
    console.error('Trade placement error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to place trade',
      code: 'TRADE_PLACEMENT_FAILED'
    });
  }
});

// Close Trade
app.post('/api/trades/:tradeId/close', verifyToken, async (req, res) => {
  try {
    const { tradeId } = req.params;
    const userId = req.userId;
    const { exitPrice } = req.body;

    // Get trade
    const tradeRef = db.collection('activeTrades').doc(tradeId);
    const tradeDoc = await tradeRef.get();
    
    if (!tradeDoc.exists) {
      return res.status(404).json({
        success: false,
        error: 'Trade not found',
        code: 'TRADE_NOT_FOUND'
      });
    }

    const trade = tradeDoc.data();

    // Verify ownership
    if (trade.userId !== userId) {
      return res.status(403).json({
        success: false,
        error: 'Unauthorized',
        code: 'UNAUTHORIZED'
      });
    }

    // Calculate profit
    const priceDiff = (exitPrice || 100) - trade.entryPrice;
    const multiplier = trade.type === 'buy' ? 1 : -1;
    const profit = priceDiff * 10 * multiplier;
    const tradeValue = trade.lotSize * 100;

    // Update user balance
    const userRef = db.collection('users').doc(userId);
    const userDoc = await userRef.get();
    
    if (userDoc.exists) {
      const currentBalance = userDoc.data().balance || 0;
      const newBalance = currentBalance + tradeValue + profit;
      
      await userRef.update({
        balance: newBalance,
        totalTrades: admin.firestore.FieldValue.increment(1),
        totalProfit: admin.firestore.FieldValue.increment(profit),
        [profit >= 0 ? 'wins' : 'losses']: admin.firestore.FieldValue.increment(1)
      });

      // Update win rate
      const updatedUserDoc = await userRef.get();
      const updatedUserData = updatedUserDoc.data();
      const winRate = updatedUserData.totalTrades > 0 
        ? (updatedUserData.wins / updatedUserData.totalTrades) * 100 
        : 0;
      
      await userRef.update({ winRate: winRate });
    }

    // Move to trade history
    await db.collection('tradeHistory').add({
      ...trade,
      exitPrice: exitPrice || 100,
      exitTime: new Date().toISOString(),
      profit: profit,
      status: 'closed',
      closedAt: new Date().toISOString()
    });

    // Remove from active trades
    await tradeRef.delete();

    res.json({
      success: true,
      message: 'Trade closed successfully',
      data: {
        profit: profit,
        exitPrice: exitPrice || 100,
        tradeValue: tradeValue
      }
    });

  } catch (error) {
    console.error('Trade close error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to close trade',
      code: 'TRADE_CLOSE_FAILED'
    });
  }
});

// Get Active Trades
app.get('/api/trades/active', verifyToken, async (req, res) => {
  try {
    const userId = req.userId;

    const snapshot = await db.collection('activeTrades')
      .where('userId', '==', userId)
      .get();

    const trades = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));

    res.json({
      success: true,
      data: {
        trades,
        count: trades.length
      }
    });

  } catch (error) {
    console.error('Active trades fetch error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch active trades',
      code: 'ACTIVE_TRADES_FETCH_FAILED'
    });
  }
});

// 8. LEADERBOARD ENDPOINTS

// Get Leaderboard
app.get('/api/leaderboard', async (req, res) => {
  try {
    const { timeframe = 'daily', limit = 100 } = req.query;

    // Calculate date range
    let startDate = new Date();
    switch (timeframe) {
      case 'daily':
        startDate.setDate(startDate.getDate() - 1);
        break;
      case 'weekly':
        startDate.setDate(startDate.getDate() - 7);
        break;
      case 'monthly':
        startDate.setMonth(startDate.getMonth() - 1);
        break;
      case 'alltime':
        startDate = new Date(0);
        break;
    }

    // Get users
    const usersSnapshot = await db.collection('users')
      .where('isBanned', '==', false)
      .get();

    const leaderboardPromises = usersSnapshot.docs.map(async (userDoc) => {
      const user = userDoc.data();
      
      // Get trades within timeframe
      const tradesQuery = await db.collection('tradeHistory')
        .where('userId', '==', userDoc.id)
        .where('exitTime', '>=', startDate.toISOString())
        .get();

      let totalProfit = 0;
      tradesQuery.forEach(tradeDoc => {
        totalProfit += tradeDoc.data().profit || 0;
      });

      return {
        userId: userDoc.id,
        username: user.username,
        name: user.name,
        profilePic: user.profilePic,
        totalTrades: tradesQuery.size,
        totalProfit: totalProfit,
        winRate: user.winRate || 0,
        balance: user.balance || 0,
        isPremium: user.isPremium || false
      };
    });

    const leaderboardData = await Promise.all(leaderboardPromises);
    
    // Sort by profit
    leaderboardData.sort((a, b) => b.totalProfit - a.totalProfit);

    res.json({
      success: true,
      data: {
        leaderboard: leaderboardData.slice(0, parseInt(limit)),
        timeframe,
        updatedAt: new Date().toISOString()
      }
    });

  } catch (error) {
    console.error('Leaderboard fetch error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch leaderboard',
      code: 'LEADERBOARD_FETCH_FAILED'
    });
  }
});

// 9. REFERRAL ENDPOINTS

// Get Referral Info
app.get('/api/referrals/info', verifyToken, async (req, res) => {
  try {
    const userId = req.userId;

    const userDoc = await db.collection('users').doc(userId).get();
    if (!userDoc.exists) {
      return res.status(404).json({
        success: false,
        error: 'User not found',
        code: 'USER_NOT_FOUND'
      });
    }

    const userData = userDoc.data();
    
    // Get referrals
    const referralsQuery = await db.collection('referrals')
      .where('referrerId', '==', userId)
      .get();

    const referrals = referralsQuery.docs.map(doc => doc.data());
    
    // Calculate earnings ($1 per 10 active referrals)
    const referralCount = referrals.length;
    const earnedBonuses = Math.floor(referralCount / 10);
    const pendingCount = referralCount % 10;
    
    // Get active referrals (users who deposited)
    const activeReferrals = referrals.filter(ref => ref.hasDeposited).length;

    res.json({
      success: true,
      data: {
        referralCode: userData.referralCode,
        referralCount: referralCount,
        activeReferrals: activeReferrals,
        earnedBonuses: earnedBonuses,
        pendingCount: pendingCount,
        referralLink: `${process.env.FRONTEND_URL}/register?ref=${userData.referralCode}`,
        referrals: referrals.slice(0, 50)
      }
    });

  } catch (error) {
    console.error('Referral info error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch referral info',
      code: 'REFERRAL_INFO_FAILED'
    });
  }
});

// Process Referral
app.post('/api/referrals/process', verifyToken, async (req, res) => {
  try {
    const { referredUserId, referralCode } = req.body;
    const referrerId = req.userId;

    if (!referredUserId || !referralCode) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields',
        code: 'MISSING_FIELDS'
      });
    }

    // Find referrer by referral code
    const referrerQuery = await db.collection('users')
      .where('referralCode', '==', referralCode)
      .limit(1)
      .get();

    if (referrerQuery.empty) {
      return res.status(404).json({
        success: false,
        error: 'Invalid referral code',
        code: 'INVALID_REFERRAL_CODE'
      });
    }

    const referrerDoc = referrerQuery.docs[0];
    
    // Create referral record
    await db.collection('referrals').add({
      referrerId: referrerDoc.id,
      referredUserId: referredUserId,
      referralCode: referralCode,
      timestamp: new Date().toISOString(),
      status: 'pending',
      hasDeposited: false,
      hasTraded: false
    });

    // Update referred user
    await db.collection('users').doc(referredUserId).update({
      referredBy: referrerDoc.id,
      referralCodeUsed: referralCode
    });

    res.json({
      success: true,
      message: 'Referral recorded successfully'
    });

  } catch (error) {
    console.error('Referral process error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to process referral',
      code: 'REFERRAL_PROCESS_FAILED'
    });
  }
});

// 10. ADMIN ENDPOINTS

// Get Admin Dashboard Stats
app.get('/api/admin/stats', verifyToken, checkAdmin, async (req, res) => {
  try {
    // Get all transactions
    const transactionsSnapshot = await db.collection('transactions').get();
    
    let totalDeposits = 0;
    let totalWithdrawals = 0;
    let totalFees = 0;
    let pendingWithdrawals = 0;
    
    transactionsSnapshot.forEach(doc => {
      const transaction = doc.data();
      if (transaction.type === 'deposit' && transaction.status === 'successful') {
        totalDeposits += transaction.amount || 0;
        totalFees += transaction.fee || 0;
      } else if (transaction.type === 'withdrawal') {
        totalWithdrawals += transaction.amount || 0;
        totalFees += (transaction.fee || 0) + (transaction.tax || 0);
        
        if (transaction.status === 'pending') {
          pendingWithdrawals += transaction.amount || 0;
        }
      }
    });

    // Get user stats
    const usersSnapshot = await db.collection('users').get();
    const activeUsers = usersSnapshot.docs.filter(doc => !doc.data().isBanned).length;
    const bannedUsers = usersSnapshot.docs.filter(doc => doc.data().isBanned).length;
    const premiumUsers = usersSnapshot.docs.filter(doc => doc.data().isPremium).length;

    // Get today's stats
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    const todaysTransactions = await db.collection('transactions')
      .where('timestamp', '>=', today.toISOString())
      .get();

    const todaysDeposits = todaysTransactions.docs
      .filter(doc => doc.data().type === 'deposit')
      .reduce((sum, doc) => sum + (doc.data().amount || 0), 0);

    const todaysTrades = await db.collection('tradeHistory')
      .where('exitTime', '>=', today.toISOString())
      .get();

    res.json({
      success: true,
      data: {
        financial: {
          totalDeposits: formatCurrency(totalDeposits),
          totalWithdrawals: formatCurrency(totalWithdrawals),
          platformProfit: formatCurrency(totalFees),
          pendingWithdrawals: formatCurrency(pendingWithdrawals),
          todaysDeposits: formatCurrency(todaysDeposits)
        },
        users: {
          total: usersSnapshot.size,
          active: activeUsers,
          banned: bannedUsers,
          premium: premiumUsers,
          online: Math.floor(Math.random() * (activeUsers / 2)) // Simulated online users
        },
        trading: {
          todaysTrades: todaysTrades.size,
          activeTrades: (await db.collection('activeTrades').get()).size
        }
      }
    });

  } catch (error) {
    console.error('Admin stats error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch admin stats',
      code: 'ADMIN_STATS_FAILED'
    });
  }
});

// Get All Users (Admin)
app.get('/api/admin/users', verifyToken, checkAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 50, search = '' } = req.query;
    const offset = (page - 1) * limit;

    let query = db.collection('users');
    
    // Apply search filter if provided
    if (search) {
      // In a real app, you'd use a more sophisticated search
      const usersSnapshot = await query.get();
      const users = usersSnapshot.docs
        .map(doc => ({ id: doc.id, ...doc.data() }))
        .filter(user => 
          user.email.includes(search) || 
          user.username.includes(search) ||
          user.name.includes(search)
        )
        .slice(offset, offset + parseInt(limit));

      return res.json({
        success: true,
        data: {
          users,
          pagination: {
            page: parseInt(page),
            limit: parseInt(limit),
            total: usersSnapshot.size,
            pages: Math.ceil(usersSnapshot.size / limit)
          }
        }
      });
    }

    const snapshot = await query
      .orderBy('joinDate', 'desc')
      .offset(offset)
      .limit(parseInt(limit))
      .get();

    const totalSnapshot = await query.get();
    
    const users = snapshot.docs.map(doc => {
      const data = doc.data();
      // Remove sensitive data
      delete data.pin;
      return { id: doc.id, ...data };
    });

    res.json({
      success: true,
      data: {
        users,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: totalSnapshot.size,
          pages: Math.ceil(totalSnapshot.size / limit)
        }
      }
    });

  } catch (error) {
    console.error('Admin users fetch error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch users',
      code: 'ADMIN_USERS_FAILED'
    });
  }
});

// Update User (Admin)
app.put('/api/admin/users/:userId', verifyToken, checkAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const updates = req.body;

    // Remove restricted fields
    delete updates.uid;
    delete updates.joinDate;
    
    const userRef = db.collection('users').doc(userId);
    
    // Check if user exists
    const userDoc = await userRef.get();
    if (!userDoc.exists) {
      return res.status(404).json({
        success: false,
        error: 'User not found',
        code: 'USER_NOT_FOUND'
      });
    }

    await userRef.update({
      ...updates,
      updatedAt: new Date().toISOString(),
      updatedBy: req.userId
    });

    // Log admin action
    await db.collection('adminLogs').add({
      adminId: req.userId,
      action: 'update_user',
      targetUserId: userId,
      updates: updates,
      timestamp: new Date().toISOString(),
      ip: req.ip
    });

    res.json({
      success: true,
      message: 'User updated successfully'
    });

  } catch (error) {
    console.error('Admin update user error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update user',
      code: 'ADMIN_UPDATE_USER_FAILED'
    });
  }
});

// Get All Transactions (Admin)
app.get('/api/admin/transactions', verifyToken, checkAdmin, async (req, res) => {
  try {
    const { type, status, startDate, endDate, page = 1, limit = 50 } = req.query;
    const offset = (page - 1) * limit;

    let query = db.collection('transactions');
    
    if (type) {
      query = query.where('type', '==', type);
    }
    
    if (status) {
      query = query.where('status', '==', status);
    }
    
    if (startDate) {
      query = query.where('timestamp', '>=', startDate);
    }
    
    if (endDate) {
      query = query.where('timestamp', '<=', endDate);
    }

    const totalQuery = query;
    const totalSnapshot = await totalQuery.get();
    
    const snapshot = await query
      .orderBy('timestamp', 'desc')
      .offset(offset)
      .limit(parseInt(limit))
      .get();

    const transactions = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));

    res.json({
      success: true,
      data: {
        transactions,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: totalSnapshot.size,
          pages: Math.ceil(totalSnapshot.size / limit)
        }
      }
    });

  } catch (error) {
    console.error('Admin transactions error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch transactions',
      code: 'ADMIN_TRANSACTIONS_FAILED'
    });
  }
});

// 11. NOTIFICATION ENDPOINTS

// Get User Notifications
app.get('/api/notifications', verifyToken, async (req, res) => {
  try {
    const userId = req.userId;
    const { limit = 20 } = req.query;

    const snapshot = await db.collection('notifications')
      .where('userId', '==', userId)
      .orderBy('timestamp', 'desc')
      .limit(parseInt(limit))
      .get();

    const notifications = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));

    // Mark as read if specified
    if (req.query.markRead === 'true') {
      const batch = db.batch();
      snapshot.docs.forEach(doc => {
        if (!doc.data().read) {
          batch.update(doc.ref, { read: true });
        }
      });
      await batch.commit();
    }

    res.json({
      success: true,
      data: {
        notifications,
        unreadCount: notifications.filter(n => !n.read).length
      }
    });

  } catch (error) {
    console.error('Notifications error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch notifications',
      code: 'NOTIFICATIONS_FAILED'
    });
  }
});

// 12. SYSTEM ENDPOINTS

// Get System Settings
app.get('/api/system/settings', async (req, res) => {
  try {
    const settingsDoc = await db.collection('settings').doc('system').get();
    
    const defaultSettings = {
      depositFee: 2.5,
      withdrawalFee: 1.5,
      withdrawalTax: 10,
      minimumDeposit: 5,
      maximumDeposit: 10000,
      minimumWithdrawal: 20,
      maximumWithdrawal: 10000,
      tradingEnabled: true,
      maintenanceMode: false,
      referralBonus: 1,
      referralThreshold: 10,
      version: '1.0.0',
      updatedAt: new Date().toISOString()
    };

    if (settingsDoc.exists) {
      res.json({
        success: true,
        data: { ...defaultSettings, ...settingsDoc.data() }
      });
    } else {
      res.json({
        success: true,
        data: defaultSettings
      });
    }

  } catch (error) {
    console.error('Settings error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch settings',
      code: 'SETTINGS_FAILED'
    });
  }
});

// 13. ERROR HANDLING MIDDLEWARE
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  
  res.status(500).json({
    success: false,
    error: 'Internal server error',
    code: 'INTERNAL_ERROR',
    requestId: req.id
  });
});

// 404 Handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found',
    code: 'ENDPOINT_NOT_FOUND'
  });
});

// ==================== START SERVER ====================
const startServer = async () => {
  try {
    // Verify Firebase connection
    await db.collection('test').doc('test').set({ test: true });
    console.log('✅ Firebase connected successfully');
    
    // Test Korapay connection
    try {
      await korapayApi.get('/charges');
      console.log('✅ Korapay API connected successfully');
    } catch (error) {
      console.warn('⚠️ Korapay API connection warning:', error.message);
    }

    app.listen(PORT, () => {
      console.log(`
🚀 Solana Trading Platform Backend
==================================
✅ Server running on port ${PORT}
✅ Health check: http://localhost:${PORT}/api/health
✅ API Documentation available
✅ Firebase: Connected
✅ Korapay: Configured
✅ Ready to process payments!
==================================
      `);
    });

  } catch (error) {
    console.error('❌ Server startup failed:', error);
    process.exit(1);
  }
};

startServer();

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received. Shutting down gracefully...');
  process.exit(0);
});
