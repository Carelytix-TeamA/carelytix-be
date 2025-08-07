import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import router from "./routes/auth.router";
import {errorMiddleware} from "@packages/error-handler/error-handler-middleware";
const app = express();

app.use(
  cors({
    origin: ["http://localhost:3000"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());
app.get("/", (req, res) => {
  res.send({message: "Hello Auth Service API"});
});
// Routes
app.use("/api", router);

app.use(errorMiddleware);
const port = process.env.PORT ? Number(process.env.PORT) : 6001;
const server = app.listen(port, () => {
  console.log(`Auth service running at http://localhost:${port}/api`);
});
server.on("error", (err) => console.error("Server Error:", err));
