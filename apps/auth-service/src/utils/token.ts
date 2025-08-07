import {AuthError} from "@packages/error-handler";
import prisma from "@packages/lib/prisma";
import jwt, {SignOptions} from "jsonwebtoken";

interface GenerateTokensInput {
  id: string;
  email: string;
  userAgent?: string;
  ipAddress?: string;
}

interface AuthTokens {
  accessToken: string;
  refreshToken: string;
}

export const generateTokens = async ({
  id,
  email,
  userAgent,
  ipAddress,
}: GenerateTokensInput): Promise<AuthTokens> => {
  try {
    const payload = {id, email};
    const jwtAccessTokenSecret = process.env.ACCESS_TOKEN_SECRET as string;
    const jwtRefreshTokenSecret = process.env.REFRESH_TOKEN_SECRET as string;
    // Access token options
    const accessTokenOptions: SignOptions = {
      expiresIn: Number(process.env.ACCESS_TOKEN_EXPIRES_IN) || "15m",
    };

    const accessToken = jwt.sign(
      payload,
      jwtAccessTokenSecret,
      accessTokenOptions
    ) as string;

    // Refresh token options
    const refreshTokenOptions: SignOptions = {
      expiresIn: Number(process.env.REFRESH_TOKEN_EXPIRES_IN) || "7d",
    };

    const refreshToken = jwt.sign(
      payload,
      jwtRefreshTokenSecret,
      refreshTokenOptions
    ) as string;

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    // Save refresh token
    await prisma.refreshToken.create({
      data: {
        userId: id,
        token: refreshToken,
        expiresAt,
        userAgent,
        ipAddress,
      },
    });

    return {
      accessToken,
      refreshToken,
    };
  } catch (error) {
    console.log(error);
    throw new AuthError("Failed to generate tokens");
  }
};

interface RefreshTokenInput {
  refreshToken: string;
  userAgent?: string;
  ipAddress?: string;
}
export const refreshAuthToken = async ({
  refreshToken,
  userAgent,
  ipAddress,
}: RefreshTokenInput): Promise<AuthTokens> => {
  try {
    const jwtAccessTokenSecret = process.env.ACCESS_TOKEN_SECRET as string;
    const jwtRefreshTokenSecret = process.env.REFRESH_TOKEN_SECRET as string;
    let decoded: any;
    try {
      decoded = jwt.verify(refreshToken, jwtRefreshTokenSecret);
    } catch (err) {
      throw new AuthError("Invalid or expired refresh token");
    }

    // Check if refresh token exists in DB
    const existingToken = await prisma.refreshToken.findUnique({
      where: {token: refreshToken},
    });

    if (!existingToken) {
      throw new AuthError("Refresh token not found or already revoked");
    }

    const {id, email} = decoded;

    // Generate new tokens
    const newAccessToken = jwt.sign({id, email}, jwtAccessTokenSecret, {
      expiresIn: Number(process.env.ACCESS_TOKEN_EXPIRES_IN) || "15m",
    });

    const newRefreshToken = jwt.sign({id, email}, jwtRefreshTokenSecret, {
      expiresIn: Number(process.env.REFRESH_TOKEN_EXPIRES_IN) || "7d",
    });

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    await prisma.$transaction([
      prisma.refreshToken.delete({
        where: {token: refreshToken},
      }),
      prisma.refreshToken.create({
        data: {
          userId: id,
          token: newRefreshToken,
          expiresAt,
          userAgent,
          ipAddress,
        },
      }),
    ]);

    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    };
  } catch (error) {
    throw new AuthError("Failed to refresh tokens");
  }
};
export interface JWTPayload {
  id: string;
  email: string;
  iat: number;
  exp: number;
}
export const validateToken = async ({
  token,
}: {
  token: string;
}): Promise<JWTPayload> => {
  try {
    const jwtAccessTokenSecret = process.env.ACCESS_TOKEN_SECRET as string;
    const decoded = jwt.verify(token, jwtAccessTokenSecret) as JWTPayload;
    const user = await prisma.user.findUnique({
      where: {id: decoded.id},
    });

    if (!user) {
      throw new AuthError("User not found for this token!");
    }
    return decoded;
  } catch (error) {
    throw new AuthError("Invalid or expired token");
  }
};
