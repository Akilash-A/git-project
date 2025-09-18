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
  Provide a security score (safe or unsafe) and detailed analysis.

  IP Address: {{{ipAddress}}}
  \n  Respond in the following format:
  {
   "securityScore": "safe" | "unsafe",
   "analysisDetails": "Detailed analysis..."
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
