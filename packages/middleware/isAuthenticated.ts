import prisma from "@packages/lib/prisma";
import {NextFunction, Request, Response} from "express";
import jwt from "jsonwebtoken";

const isAuthenticated = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const token =
      req.cookies["access-token"] || req.headers.authorization?.split(" ")[1];
    if (!token) {
      return res.status(401).json({message: "Unauthorized"});
    }
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET!) as {
      id: string;
      email: string;
    };
    if (!decoded) {
      return res.status(401).json({message: " Unauthorized! Invalid token."});
    }
    const account = await prisma.user.findUnique({where: {id: decoded.id}});
    if (!account) {
      return res.status(401).json({message: "Account not found!"});
    }
    req.user = account;
    return next();
  } catch (error) {
    return res
      .status(401)
      .json({message: "Unauthorized! Token expired or Invalid token."});
  }
};

export default isAuthenticated;
