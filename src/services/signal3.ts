import crypto from 'crypto';

/**
 * Analyzes email attachments by computing their SHA-256 hash
 * and looking up the hash on VirusTotal.
 *
 * @param attachments Array of attachment objects from the payload.
 * @returns A promise resolving to the highest sub-score and explanations.
 */
export async function analyzeAttachments(attachments: any[] | undefined): Promise<{ score: number; details: string }> {
  if (!attachments || !Array.isArray(attachments) || attachments.length === 0) {
    return { score: 0, details: 'No attachments found.' };
  }

  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey || apiKey === 'mock_key_for_now') {
    return { score: 50, details: 'API Key missing. Signal skipped.' };
  }

  let highestScore = 0;
  const detailsList: string[] = [];

  for (const attachment of attachments) {
    if (!attachment.filename || !attachment.contentBase64) {
      continue;
    }

    try {
      const buffer = Buffer.from(attachment.contentBase64, 'base64');
      const hash = crypto.createHash('sha256').update(buffer).digest('hex');

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2000);

      const response = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
        method: 'GET',
        headers: {
          'x-apikey': apiKey,
        },
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (response.status === 404) {
        detailsList.push(`${attachment.filename}: Clean (Unknown to VT)`);
        continue;
      }

      if (!response.ok) {
        console.error(`[analyzeAttachments] VT API error: ${response.status} ${response.statusText}`);
        detailsList.push(`${attachment.filename}: Threat Intel API unavailable`);
        highestScore = Math.max(highestScore, 50);
        continue;
      }

      const json: any = await response.json();
      const stats = json?.data?.attributes?.last_analysis_stats;

      if (!stats) {
        detailsList.push(`${attachment.filename}: Clean`);
        continue;
      }

      const malicious = stats.malicious || 0;
      const suspicious = stats.suspicious || 0;

      let fileScore = 0;
      if (malicious > 0) {
        fileScore = 100;
        detailsList.push(`${attachment.filename}: Malicious (${malicious} vendors)`);
      } else if (suspicious > 0) {
        fileScore = 60;
        detailsList.push(`${attachment.filename}: Suspicious (${suspicious} vendors)`);
      } else {
        fileScore = 0;
        detailsList.push(`${attachment.filename}: Clean`);
      }

      highestScore = Math.max(highestScore, fileScore);

    } catch (error: any) {
      if (error.name === 'AbortError') {
        console.warn(`[analyzeAttachments] VT API request timed out for attachment: ${attachment.filename}`);
      } else {
        console.error(`[analyzeAttachments] Error fetching from VT API:`, error);
      }
      
      detailsList.push(`${attachment.filename}: Threat Intel API timeout or unavailable`);
      highestScore = Math.max(highestScore, 50);
    }
  }

  if (detailsList.length === 0) {
    return { score: 0, details: 'No valid attachments to process.' };
  }

  return { score: highestScore, details: detailsList.join(' | ') };
}
