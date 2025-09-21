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

  Scoring Guidelines:
  - 0-20: Very Safe (legitimate services, trusted organizations)
  - 21-40: Low Risk (residential IPs, minor concerns)
  - 41-60: Medium Risk (suspicious activity, potential threats)
  - 61-80: High Risk (known malicious activity, botnet members)
  - 81-100: Extreme Danger (active attacks, blacklisted, major threats)

  IP Address: {{{ipAddress}}}
  
  Respond in the following format:
  {
   "securityScore": "safe" | "unsafe",
   "dangerScore": <number 0-100>,
   "analysisDetails": "Detailed analysis explaining the danger score and specific threats..."
  }`,
});

const ipAddressSecurityScoringFlow = ai.defineFlow(
  {
    name: 'ipAddressSecurityScoringFlow',
    inputSchema: IpAddressSecurityScoringInputSchema,
    outputSchema: IpAddressSecurityScoringOutputSchema,
  },
  async input => {
    const {output} = await prompt(input);
    return output!;
  }
);
