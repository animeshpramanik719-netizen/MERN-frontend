const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const path = require('path');
const fs = require('fs');

dotenv.config({ path: path.join(__dirname, '.env') });

const app = express();

app.set('trust proxy', 1);
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Ensure uploads directories exist with absolute paths
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
if (!fs.existsSync(path.join(uploadsDir, 'avatars'))) fs.mkdirSync(path.join(uploadsDir, 'avatars'), { recursive: true });
if (!fs.existsSync(path.join(uploadsDir, 'covers'))) fs.mkdirSync(path.join(uploadsDir, 'covers'), { recursive: true });

app.use('/uploads', express.static(uploadsDir));

// Health check endpoints (helpful for Render / cloud monitoring)
app.get('/', (req, res) => {
  res.json({ message: 'PhotoGallery API is running smoothly', status: 'OK' });
});

app.get('/health', (req, res) => {
  res.status(200).send('OK');
});

// Routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/photos', require('./routes/photos'));

const PORT = process.env.PORT || 5000;

// Start server immediately so API & uploads are always accessible
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT} (0.0.0.0)`);
});

// Asynchronously connect to MongoDB without blocking server listening
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/photo-gallery')
  .then(() => {
    console.log('Connected to MongoDB');
  })
  .catch((err) => {
    console.warn('MongoDB connection notice (offline/local fallback):', err.message);
  });
