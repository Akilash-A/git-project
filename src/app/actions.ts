
"use server";

import {
  ipAddressSecurityScoring,
  type IpAddressSecurityScoringInput,
  type IpAddressSecurityScoringOutput,
} from "@/ai/flows/ip-address-security-scoring";

export async function getIpSecurityScore(
  input: IpAddressSecurityScoringInput
): Promise<IpAddressSecurityScoringOutput> {
  // In a real application, you might add more validation or error handling here.
  const result = await ipAddressSecurityScoring(input);
  return result;
}
