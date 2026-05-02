import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import scanRouter from './routes/scanRouter';

const app = express();
const PORT = process.env.PORT || 3000;

// ──────────────────────────────────────────────
// Global Middleware
// ──────────────────────────────────────────────

// SECURITY: Limit JSON body size to 15 MB to mitigate DoS via oversized payloads.
app.use(express.json({ limit: '15mb' }));

// Allow cross-origin requests (will be tightened for production).
app.use(cors());

// ──────────────────────────────────────────────
// Routes
// ──────────────────────────────────────────────

app.use('/api/scan', scanRouter);

// Health-check endpoint
app.get('/health', (_req, res) => {
  res.status(200).json({ status: 'ok' });
});

// ──────────────────────────────────────────────
// Start Server
// ──────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`🚀 Upwind Email Scorer backend listening on http://localhost:${PORT}`);
});

export default app;
