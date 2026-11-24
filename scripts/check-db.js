import 'dotenv/config';
import mongoose from 'mongoose';
if (!process.env.MONGODB_URI || process.env.MONGODB_URI.includes('USER:PASSWORD')) {
  console.error('MONGODB_URI missing or placeholder. Copy .env.example to .env and paste your MongoDB Atlas connection URI.');
  process.exit(1);
}
try {
  await mongoose.connect(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 10000 });
  await mongoose.connection.db.admin().ping();
  console.log(`MongoDB connected successfully. Database: ${mongoose.connection.name}`);
  console.log('Collections will be created automatically on first document insert.');
  await mongoose.disconnect();
} catch (error) {
  console.error('MongoDB connection failed:', error.message);
  process.exitCode = 1;
  await mongoose.disconnect().catch(() => {});
}
