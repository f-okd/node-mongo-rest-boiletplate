"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
require("dotenv/config.js");
const mongoose_1 = __importDefault(require("mongoose"));
const index_1 = __importDefault(require("./index"));
const PORT = process.env.PORT || 3000;
const DB_URL = process.env.DB_URL;
const DB_PASSWORD = process.env.DB_PASSWORD;
const DB = DB_URL.replace('<password>', DB_PASSWORD);
mongoose_1.default
    .connect(DB)
    .then(() => console.log('[server] DB connection successful!'));
index_1.default.listen(PORT, () => __awaiter(void 0, void 0, void 0, function* () {
    console.log(`[server] Listening on port: ${PORT}\n[server] Environment: ${process.env.NODE_ENV}`);
}));
const port = process.env.PORT || 3000;
const server = index_1.default.listen(port, () => {
    console.log(`App running on port ${port}`);
});
//event listener
process.on('unhandledRejection', (err) => {
    console.log('UNHANDLED REJECTION * SHUTTING DOWN');
    console.log(err.name, err.message);
    server.close(() => process.exit(1));
});
process.on('uncaughtException', (err) => {
    console.log(err.name, err.message);
    console.log('UNCAUGHT EXCEPTION * SHUTTING DOWN');
    process.exit(1);
});
