import serverless from "serverless-http";
import app from "../server.js"; // adjust path if your file is named differently

export const handler = serverless(app);
