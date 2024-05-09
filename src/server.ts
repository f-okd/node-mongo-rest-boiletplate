import 'dotenv/config.js';
import mongoose from 'mongoose';

import app from './index';

//Load env variables from .env file https://www.npmjs.com/package/dotenv#-install
const PORT = process.env.PORT || 3000;
const DB_URL = process.env.DB_URL as string;
const DB_PASSWORD = process.env.DB_PASSWORD as string;
const DB = DB_URL.replace('<PASSWORD>', DB_PASSWORD);

mongoose
  .connect(DB)
  .then(() => console.log('[server] DB connection successful!'));
app.listen(PORT, async () => {
  console.log(
    `[server] Listening on port: ${PORT}\n[server] Environment: ${process.env.NODE_ENV}`,
  );
});

// //event listener
// process.on('unhandledRejection', (err: Error) => {
//   console.log('UNHANDLED REJECTION * SHUTTING DOWN');
//   console.log(err.name, err.message);
//   server.close(() => process.exit(1));
// });

// process.on('uncaughtException', (err) => {
//   console.log(err.name, err.message);
//   console.log('UNCAUGHT EXCEPTION * SHUTTING DOWN');
//   process.exit(1);
// });
