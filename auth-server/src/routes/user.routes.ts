import { Router } from "express";
import { getMe } from "../controllers/user.controller.js";
import { authMiddleware } from "../middlewares/auth.middleware.js";

export const userRouter = Router();

userRouter.get("/me", authMiddleware, getMe);
