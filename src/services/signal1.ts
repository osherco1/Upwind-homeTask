/**
 * Analyzes email metadata and body for spoofing indicators and phishing patterns.
 * 
 * @param payload The incoming request body payload containing email body and headers.
 * @returns The calculated risk score (0-100) and an explanation string.
 */
export function analyzeMetadata(payload: any): { score: number; details: string } {
  let score = 0;
  const reasons: string[] = [];

  // Safely extract properties handling potentially undefined payload
  const headers = payload?.headers || {};
  const body = payload?.body || '';

  // 1. SPF Check
  const receivedSpf = typeof headers.receivedSpf === 'string' ? headers.receivedSpf.toLowerCase() : '';
  if (receivedSpf.includes('fail') || receivedSpf.includes('softfail')) {
    score += 30;
    reasons.push('SPF check failed or softfailed');
  }

  // 2. Reply-To Mismatch
  const from = typeof headers.from === 'string' ? headers.from.toLowerCase() : '';
  const replyTo = typeof headers.replyTo === 'string' ? headers.replyTo.toLowerCase() : '';

  if (from && replyTo && from !== replyTo) {
    const extractDomain = (emailString: string) => {
      const match = emailString.match(/@([\w.-]+)/);
      return match ? match[1] : null;
    };

    const fromDomain = extractDomain(from);
    const replyToDomain = extractDomain(replyTo);

    if (fromDomain && replyToDomain && fromDomain !== replyToDomain) {
      score += 40;
      reasons.push('Reply-To domain does not match From domain');
    }
  }

  // 3. Body Pattern Matching
  const urgencyRegex = /\b(urgent|act now|immediate|suspended)\b/i;
  if (typeof body === 'string' && urgencyRegex.test(body)) {
    score += 15;
    reasons.push('Body contains urgency patterns');
  }

  const credentialRegex = /\b(password|login|verify)\b/i;
  if (typeof body === 'string' && credentialRegex.test(body)) {
    score += 15;
    reasons.push('Body contains credential harvesting terms');
  }

  // Cap the final score at 100
  score = Math.min(score, 100);

  const details = reasons.length > 0 
    ? reasons.join('. ') + '.' 
    : 'No suspicious metadata or patterns detected.';

  return { score, details };
}
