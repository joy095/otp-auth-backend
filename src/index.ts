/** @format */

import express from "express";
import "dotenv/config";
import cookieParser from "cookie-parser";
import cors from "cors";

import userRoutes from "./routes/userRoute";
import { corsOptions } from "./config/cors";

const app = express();
app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser()); // To parse cookies

app.use("/api/users", userRoutes);

const port = process.env.PORT;

// Start the server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
