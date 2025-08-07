import express, {Router} from "express";
import {
  userRegistration,
  refreshToken,
  loginUser,
  logoutUser,
} from "../controller/auth.controller";

const router: Router = express.Router();

router.post("/user-registration", userRegistration);
router.post("/login-user", loginUser);
router.post("/refresh-token-user", refreshToken);
router.post("/logout-user", logoutUser);

export default router;
