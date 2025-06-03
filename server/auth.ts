import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Express } from "express";
import session from "express-session";
import { scrypt, randomBytes, timingSafeEqual } from "crypto";
import { promisify } from "util";
import { storage } from "./storage";
import { User as SelectUser, insertUserSchema } from "@shared/schema";
import { z } from "zod";

// Extend Express User interface
declare global {
  namespace Express {
    interface User extends SelectUser {}
  }
}

const scryptAsync = promisify(scrypt);

/**
 * Hash password using scrypt with salt
 * @param password - Plain text password
 * @returns Hashed password with salt
 */
async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16).toString("hex");
  const buf = (await scryptAsync(password, salt, 64)) as Buffer;
  return `${buf.toString("hex")}.${salt}`;
}

/**
 * Compare supplied password with stored hash
 * @param supplied - Plain text password to verify
 * @param stored - Stored hash with salt
 * @returns True if passwords match
 */
async function comparePasswords(supplied: string, stored: string): Promise<boolean> {
  const [hashed, salt] = stored.split(".");
  const hashedBuf = Buffer.from(hashed, "hex");
  const suppliedBuf = (await scryptAsync(supplied, salt, 64)) as Buffer;
  return timingSafeEqual(hashedBuf, suppliedBuf);
}

/**
 * Set up authentication middleware and routes
 * @param app - Express application instance
 */
export function setupAuth(app: Express): void {
  // Configure session
  const sessionSettings: session.SessionOptions = {
    secret: process.env.SESSION_SECRET || "ai-spm-secret-key-change-in-production",
    resave: false,
    saveUninitialized: false,
    store: storage.sessionStore,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    },
  };

  app.set("trust proxy", 1);
  app.use(session(sessionSettings));
  app.use(passport.initialize());
  app.use(passport.session());

  // Configure passport local strategy
  passport.use(
    new LocalStrategy(
      {
        usernameField: "username", // Can be username or email
        passwordField: "password",
      },
      async (username, password, done) => {
        try {
          // Try to find user by username or email
          let user = await storage.getUserByUsername(username);
          if (!user) {
            user = await storage.getUserByEmail(username);
          }

          if (!user) {
            return done(null, false, { message: "Invalid credentials" });
          }

          if (!user.isActive) {
            return done(null, false, { message: "Account is deactivated" });
          }

          const isValid = await comparePasswords(password, user.password);
          if (!isValid) {
            return done(null, false, { message: "Invalid credentials" });
          }

          // Log successful login
          await storage.createAuditLog({
            userId: user.id,
            action: "login",
            resourceType: "user",
            resourceId: user.id,
            details: { loginMethod: "local" },
          });

          return done(null, user);
        } catch (error) {
          return done(error);
        }
      }
    )
  );

  // Serialize user for session
  passport.serializeUser((user, done) => done(null, user.id));

  // Deserialize user from session
  passport.deserializeUser(async (id: number, done) => {
    try {
      const user = await storage.getUser(id);
      done(null, user);
    } catch (error) {
      done(error);
    }
  });

  // Register route
  app.post("/api/register", async (req, res, next) => {
    try {
      // Validate input
      const validatedData = insertUserSchema.parse(req.body);

      // Check if username already exists
      const existingUsername = await storage.getUserByUsername(validatedData.username);
      if (existingUsername) {
        return res.status(400).json({ error: "Username already exists" });
      }

      // Check if email already exists
      const existingEmail = await storage.getUserByEmail(validatedData.email);
      if (existingEmail) {
        return res.status(400).json({ error: "Email already exists" });
      }

      // Hash password and create user
      const hashedPassword = await hashPassword(validatedData.password);
      const user = await storage.createUser({
        ...validatedData,
        password: hashedPassword,
      });

      // Log user registration
      await storage.createAuditLog({
        userId: user.id,
        action: "register",
        resourceType: "user",
        resourceId: user.id,
        details: { registrationMethod: "local" },
      });

      // Auto-login after registration
      req.login(user, (err) => {
        if (err) return next(err);
        
        // Remove password from response
        const { password, ...userResponse } = user;
        res.status(201).json(userResponse);
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ 
          error: "Validation failed", 
          details: error.errors 
        });
      }
      next(error);
    }
  });

  // Login route
  app.post("/api/login", (req, res, next) => {
    passport.authenticate("local", (err: any, user: SelectUser, info: any) => {
      if (err) {
        return next(err);
      }
      if (!user) {
        return res.status(401).json({ error: info?.message || "Authentication failed" });
      }

      req.logIn(user, (err) => {
        if (err) {
          return next(err);
        }
        
        // Remove password from response
        const { password, ...userResponse } = user;
        res.status(200).json(userResponse);
      });
    })(req, res, next);
  });

  // Logout route
  app.post("/api/logout", async (req, res, next) => {
    const userId = req.user?.id;
    
    req.logout((err) => {
      if (err) return next(err);

      // Log logout if user was authenticated
      if (userId) {
        storage.createAuditLog({
          userId,
          action: "logout",
          resourceType: "user",
          resourceId: userId,
          details: { logoutMethod: "manual" },
        }).catch(console.error); // Don't block response for audit log failures
      }

      res.sendStatus(200);
    });
  });

  // Get current user route
  app.get("/api/user", (req, res) => {
    if (!req.isAuthenticated()) {
      return res.sendStatus(401);
    }

    // Remove password from response
    const { password, ...userResponse } = req.user!;
    res.json(userResponse);
  });

  // Update user profile route
  app.patch("/api/user/profile", async (req, res, next) => {
    if (!req.isAuthenticated()) {
      return res.sendStatus(401);
    }

    try {
      const allowedUpdates = ["fullName", "department", "email"];
      const updates: any = {};
      
      // Only allow specific fields to be updated
      for (const field of allowedUpdates) {
        if (req.body[field] !== undefined) {
          updates[field] = req.body[field];
        }
      }

      if (Object.keys(updates).length === 0) {
        return res.status(400).json({ error: "No valid fields to update" });
      }

      // Check email uniqueness if email is being updated
      if (updates.email && updates.email !== req.user!.email) {
        const existingUser = await storage.getUserByEmail(updates.email);
        if (existingUser && existingUser.id !== req.user!.id) {
          return res.status(400).json({ error: "Email already exists" });
        }
      }

      const updatedUser = await storage.updateUser(req.user!.id, updates);
      if (!updatedUser) {
        return res.status(404).json({ error: "User not found" });
      }

      // Log profile update
      await storage.createAuditLog({
        userId: req.user!.id,
        action: "update_profile",
        resourceType: "user",
        resourceId: req.user!.id,
        details: { updatedFields: Object.keys(updates) },
      });

      // Remove password from response
      const { password, ...userResponse } = updatedUser;
      res.json(userResponse);
    } catch (error) {
      next(error);
    }
  });
}
