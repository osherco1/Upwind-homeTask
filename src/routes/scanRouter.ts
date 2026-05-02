import { Router, Request, Response } from 'express';
import { validateRequest } from '../middlewares/validateRequest';
import { auth } from '../middlewares/auth';
import { analyzeMetadata } from '../services/signal1';
import { checkSenderReputation } from '../services/signal2';
import { analyzeAttachments } from '../services/signal3';

const scanRouter = Router();

/**
 * POST /api/scan
 *
 * Accepts the email scan payload and returns a risk assessment.
 * Calculates dynamic scores for all 3 signals, computes a composite score,
 * and determines the final risk verdict.
 */
scanRouter.post('/', auth, validateRequest, async (req: Request, res: Response) => {
  const signal1Result = analyzeMetadata(req.body);
  const signal2Result = await checkSenderReputation(req.body.headers?.from);
  const signal3Result = await analyzeAttachments(req.body.attachments);

  let compositeScore = (signal1Result.score * 0.35) + (signal2Result.score * 0.30) + (signal3Result.score * 0.35);
  compositeScore = Math.round(compositeScore);

  let verdict = 'Low Risk';
  if (compositeScore >= 30 && compositeScore <= 59) {
    verdict = 'Medium Risk';
  } else if (compositeScore >= 60 && compositeScore <= 84) {
    verdict = 'High Risk';
  } else if (compositeScore >= 85 && compositeScore <= 100) {
    verdict = 'Critical Risk';
  }

  const responsePayload = {
    score: compositeScore,
    verdict: verdict,
    signals: [
      {
        name: 'Metadata & Spoofing',
        score: signal1Result.score,
        details: signal1Result.details,
      },
      {
        name: 'Sender Reputation',
        score: signal2Result.score,
        details: signal2Result.details,
      },
      {
        name: 'Attachment Analysis',
        score: signal3Result.score,
        details: signal3Result.details,
      },
    ],
  };

  res.status(200).json(responsePayload);
});

export default scanRouter;
