import 'dotenv/config';
import app, { connectDb } from './app.js';

const port = process.env.PORT || 4000;
app.listen(port, () => console.log(`AEGIS-X API listening on ${port}`));

connectDb().catch((err) => {
  console.error('MongoDB connection failed:', err.message);
});
