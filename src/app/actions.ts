
"use server";

import {
  ipAddressSecurityScoring,
  type IpAddressSecurityScoringInput,
  type IpAddressSecurityScoringOutput,
} from "@/ai/flows/ip-address-security-scoring";

export async function getIpSecurityScore(
  input: IpAddressSecurityScoringInput
): Promise<IpAddressSecurityScoringOutput> {
  try {
    const result = await ipAddressSecurityScoring(input);
    return result;
  } catch (error: any) {
    console.error('IP Security Analysis Error:', error.message);
    
    // Return fallback response for better user experience
    return {
      securityScore: 'service-unavailable',
      dangerScore: 50,
      analysisDetails: `Unable to analyze IP ${input.ipAddress} - AI analysis service is temporarily unavailable. Please try again in a few minutes. This is likely a temporary Google AI service outage.`
    };
  }
}
