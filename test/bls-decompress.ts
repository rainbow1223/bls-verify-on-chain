import { ethers } from "ethers";

/**
 * Decompress a G1 point using the EIP-2537 MAP_FP_TO_G1 precompile (0x10)
 * Input: 64 bytes (compressed G1 point)
 * Output: 128 bytes (uncompressed G1 point: x || y)
 */
export async function decompressG1UsingPrecompile(
  provider: ethers.Provider,
  compressed: Uint8Array
): Promise<string> {
  if (compressed.length !== 48) {
    throw new Error(`Compressed G1 point must be 48 bytes, got ${compressed.length}`);
  }

  // EIP-2537 MAP_FP_TO_G1 precompile at address 0x10
  // Input: 64 bytes (Fp element, but we need to extract the field element from compressed point)
  // Actually, the precompile expects an Fp element, not a compressed point
  // We need to extract the x-coordinate from the compressed point first
  
  // For compressed G1: first 48 bytes contain the x-coordinate (with sign bit)
  // We need to extract just the x-coordinate (48 bytes) and pad to 64 bytes
  const fpElement = new Uint8Array(64);
  compressed.copyWithin(fpElement, 0, 0, 48);
  
  // Call precompile 0x10 (MAP_FP_TO_G1)
  const input = ethers.hexlify(fpElement);
  const result = await provider.call({
    to: "0x0000000000000000000000000000000000000010",
    data: input,
  });

  // Result should be 128 bytes (64 bytes x || 64 bytes y)
  if (result.length !== 130) { // 0x + 128*2
    throw new Error(`Expected 128 bytes from precompile, got ${result.length}`);
  }

  return result;
}

/**
 * Decompress a G2 point using the EIP-2537 MAP_FP2_TO_G2 precompile (0x11)
 * Input: 96 bytes (compressed G2 point)
 * Output: 256 bytes (uncompressed G2 point: x_im || x_re || y_im || y_re)
 */
export async function decompressG2UsingPrecompile(
  provider: ethers.Provider,
  compressed: Uint8Array
): Promise<string> {
  if (compressed.length !== 96) {
    throw new Error(`Compressed G2 point must be 96 bytes, got ${compressed.length}`);
  }

  // EIP-2537 MAP_FP2_TO_G2 precompile at address 0x11
  // Input: 128 bytes (Fp2 element: 64 bytes u || 64 bytes u_I)
  // We need to extract the x-coordinate from the compressed point
  
  // For compressed G2: first 96 bytes contain the x-coordinate (with sign bit)
  // We need to extract just the x-coordinate and format as Fp2 (128 bytes)
  const fp2Element = new Uint8Array(128);
  // Copy the compressed point to the first 96 bytes, pad to 128
  compressed.copyWithin(fp2Element, 0, 0, 96);
  
  // Call precompile 0x11 (MAP_FP2_TO_G2)
  const input = ethers.hexlify(fp2Element);
  const result = await provider.call({
    to: "0x0000000000000000000000000000000000000011",
    data: input,
  });

  // Result should be 256 bytes
  if (result.length !== 514) { // 0x + 256*2
    throw new Error(`Expected 256 bytes from precompile, got ${result.length}`);
  }

  return result;
}

