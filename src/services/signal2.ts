/**
 * Checks the reputation of the sender domain using the VirusTotal API.
 *
 * @param fromHeader The value of the 'From' header in the email.
 * @returns A promise resolving to the sub-score and explanation.
 */
export async function checkSenderReputation(fromHeader: string | undefined): Promise<{ score: number; details: string }> {
  if (!fromHeader) {
    return { score: 0, details: 'No sender domain to check.' };
  }

  // Extract domain from "Name <user@domain.com>" or "user@domain.com"
  const match = fromHeader.match(/@([\w.-]+)/);
  const domain = match ? match[1] : null;

  if (!domain) {
    return { score: 0, details: 'No valid sender domain to check.' };
  }

  const apiKey = process.env.VIRUSTOTAL_API_KEY;

  if (!apiKey || apiKey === 'mock_key_for_now') {
    return { score: 50, details: 'API Key missing. Signal skipped.' };
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 2000);

  try {
    const response = await fetch(`https://www.virustotal.com/api/v3/domains/${domain}`, {
      method: 'GET',
      headers: {
        'x-apikey': apiKey,
      },
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      console.error(`[checkSenderReputation] VT API error: ${response.status} ${response.statusText}`);
      return { score: 50, details: 'Threat Intel API unavailable.' };
    }

    const json: any = await response.json();
    const stats = json?.data?.attributes?.last_analysis_stats;

    if (!stats) {
      return { score: 0, details: 'Domain reputation is clean (no stats available).' };
    }

    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;

    if (malicious > 0) {
      return { score: 90, details: `Domain flagged as malicious by ${malicious} vendors.` };
    } else if (suspicious > 0) {
      return { score: 60, details: `Domain flagged as suspicious by ${suspicious} vendors.` };
    }

    return { score: 0, details: 'Domain reputation is clean.' };

  } catch (error: any) {
    clearTimeout(timeoutId);
    
    if (error.name === 'AbortError') {
      console.warn(`[checkSenderReputation] VT API request timed out for domain: ${domain}`);
    } else {
      console.error(`[checkSenderReputation] Error fetching from VT API:`, error);
    }
    
    return { score: 50, details: 'Threat Intel API timeout or unavailable.' };
  }
}
