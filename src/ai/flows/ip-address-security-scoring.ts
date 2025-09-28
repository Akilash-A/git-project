'use server';

/**
 * @fileOverview Provides a security score (safe/unsafe) for a given IP address based on security reputation databases.
 *
 * - ipAddressSecurityScoring - A function that handles the IP address security scoring process.
 * - IpAddressSecurityScoringInput - The input type for the ipAddressSecurityScoring function.
 * - IpAddressSecurityScoringOutput - The return type for the ipAddressSecurityScoring function.
 */

import {ai} from '@/ai/genkit';
import {z} from 'genkit';

const IpAddressSecurityScoringInputSchema = z.object({
  ipAddress: z
    .string()
    .describe('The IP address to be analyzed for security.'),
  attackData: z
    .object({
      totalPackets: z.number().optional(),
      ddosAttacks: z.number().optional(),
      portScans: z.number().optional(),
      bruteForceAttacks: z.number().optional(),
      malwareDetections: z.number().optional(),
      connectionFloods: z.number().optional(),
      unauthorizedAccess: z.number().optional(),
      knownThreats: z.number().optional(),
      averageThreatScore: z.number().optional(),
      maxThreatScore: z.number().optional(),
      attackDetails: z.array(z.string()).optional()
    })
    .optional()
    .describe('Detailed attack pattern data from packet monitoring'),
});
export type IpAddressSecurityScoringInput = z.infer<typeof IpAddressSecurityScoringInputSchema>;

const IpAddressSecurityScoringOutputSchema = z.object({
  securityScore: z
    .string()
    .describe('A security score for the IP address, indicating whether it is safe or unsafe.'),
  dangerScore: z
    .number()
    .min(0)
    .max(100)
    .describe('A numerical danger score from 0-100, where 0 is completely safe and 100 is extremely dangerous.'),
  analysisDetails: z
    .string()
    .describe('Detailed analysis of the IP address, including any threat information.'),
});
export type IpAddressSecurityScoringOutput = z.infer<typeof IpAddressSecurityScoringOutputSchema>;

export async function ipAddressSecurityScoring(input: IpAddressSecurityScoringInput): Promise<IpAddressSecurityScoringOutput> {
  return ipAddressSecurityScoringFlow(input);
}

const prompt = ai.definePrompt({
  name: 'ipAddressSecurityScoringPrompt',
  input: {schema: IpAddressSecurityScoringInputSchema},
  output: {schema: IpAddressSecurityScoringOutputSchema},
  prompt: `You are a security expert analyzing IP addresses to determine their security risk.

  Analyze the provided IP address against security reputation databases and threat intelligence feeds to assess its risk level.
  Provide both a binary security assessment and a numerical danger score from 0-100.

  **IMPORTANT**: You now have access to REAL attack pattern data from network monitoring. Use this data heavily in your analysis - it is much more reliable than general IP reputation databases.

  Scoring Guidelines (Enhanced with Attack Data):
  - 0-20: Very Safe (legitimate services, trusted organizations, no attack patterns)
  - 21-40: Low Risk (residential IPs, minor suspicious activity, low threat scores)
  - 41-60: Medium Risk (moderate attack patterns, port scanning, some malicious activity)
  - 61-80: High Risk (multiple attack types, DDoS/brute force activity, high threat scores)
  - 81-100: Extreme Danger (active multi-vector attacks, malware, sustained hostile activity)

  **Attack Pattern Weights:**
  - DDoS Attacks: +30-50 points (depending on frequency)
  - Malware Communications: +40-60 points
  - Brute Force Attacks: +25-40 points
  - Port Scanning: +15-30 points
  - Unauthorized Access Attempts: +20-35 points
  - Known Threat Status: +10-25 points
  - Connection Floods: +20-40 points

  IP Address: {{{ipAddress}}}
  
  {{#if attackData}}
  **ATTACK PATTERN DATA:**
  - Total Monitored Packets: {{attackData.totalPackets}}
  - DDoS Attacks Detected: {{attackData.ddosAttacks}}
  - Port Scans Detected: {{attackData.portScans}}
  - Brute Force Attempts: {{attackData.bruteForceAttacks}}
  - Malware Communications: {{attackData.malwareDetections}}
  - Connection Floods: {{attackData.connectionFloods}}
  - Unauthorized Access Attempts: {{attackData.unauthorizedAccess}}
  - Known Threat Flags: {{attackData.knownThreats}}
  - Average Threat Score: {{attackData.averageThreatScore}}
  - Maximum Threat Score: {{attackData.maxThreatScore}}
  {{#if attackData.attackDetails}}
  - Attack Details: {{#each attackData.attackDetails}}{{this}}; {{/each}}
  {{/if}}
  {{/if}}
  
  Respond in the following format:
  {
   "securityScore": "safe" | "unsafe",
   "dangerScore": <number 0-100>,
   "analysisDetails": "Detailed analysis explaining the danger score, incorporating specific attack patterns detected..."
  }`,
});

const ipAddressSecurityScoringFlow = ai.defineFlow(
  {
    name: 'ipAddressSecurityScoringFlow',
    inputSchema: IpAddressSecurityScoringInputSchema,
    outputSchema: IpAddressSecurityScoringOutputSchema,
  },
  async input => {
    try {
      const {output} = await prompt(input);
      return output!;
    } catch (error: any) {
      console.error('AI Service Error:', error.message);
      
      // Provide fallback response when AI service is unavailable
      return {
        securityScore: 'neutral',
        dangerScore: 50, // Neutral score when service unavailable
        analysisDetails: 'AI analysis service is temporarily unavailable. This IP cannot be properly analyzed at the moment. Please try again later for detailed security analysis.'
      };
    }
  }
);
