import { ethers } from "ethers";

// Type definitions for BLS using @noble/curves
export type PrivateKey = Uint8Array;
export type PublicKey = Uint8Array;
export type Signature = Uint8Array;

/**
 * Helper: Convert bigint to big-endian bytes
 */
function bigintToBytesBE(value: bigint, length: number): Uint8Array {
  if (typeof value !== "bigint") throw new TypeError("value must be a bigint");
  const hex = value.toString(16).padStart(length * 2, "0");
  return Buffer.from(hex, "hex");
}

/**
 * Helper: Split 48-byte field elements into two 32-byte limbs for EIP-2537
 * EIP-2537 requires 64 bytes (two 32-byte limbs) for each Fp element
 */
function fp48ToEIP2537(b48: Uint8Array): { hi: Uint8Array; lo: Uint8Array } {
  if (b48.length !== 48) {
    throw new Error(`Expected 48 bytes, got ${b48.length}`);
  }
  // Split into high 16 bytes and low 32 bytes, pad each to 32 bytes
  const hi = new Uint8Array(32);
  const lo = new Uint8Array(32);
  hi.set(b48.slice(0, 16), 16);  // high 16 bytes → padded to 32 (at offset 16)
  lo.set(b48.slice(16, 48), 0);  // low 32 bytes → already 32 bytes
  return { hi, lo };
}

/**
 * Convert a compressed G1 public key to uncompressed EIP-2537 format
 * EIP-2537 format: 128 bytes = 64 bytes x || 64 bytes y (both big-endian)
 * 
 * Uses @noble/curves to properly decompress the point.
 */
export function g1PublicKeyToEIP2537(publicKey: PublicKey, bls: any): string {
  if (publicKey.length !== 48) {
    throw new Error(`Expected compressed G1 point (48 bytes), got ${publicKey.length} bytes`);
  }

  try {
    // Convert compressed point to hex string (no 0x prefix)
    const compressedHex = Buffer.from(publicKey).toString("hex");
    
    // Decompress using @noble/curves
    const point = bls.G1.ProjectivePoint.fromHex(compressedHex).toAffine();
    
    // Convert x and y coordinates to 48-byte big-endian
    const x48 = bigintToBytesBE(point.x, 48);
    const y48 = bigintToBytesBE(point.y, 48);
    
    // Convert to EIP-2537 format (64 bytes each = two 32-byte limbs)
    const X = fp48ToEIP2537(x48);
    const Y = fp48ToEIP2537(y48);
    
    // Concatenate: x_hi(32) || x_lo(32) || y_hi(32) || y_lo(32) = 128 bytes
    const result = Buffer.concat([X.hi, X.lo, Y.hi, Y.lo]);
    
    return "0x" + result.toString("hex");
  } catch (error: any) {
    throw new Error(`Failed to decompress G1 point: ${error.message}`);
  }
}

/**
 * Convert a compressed G2 signature to uncompressed EIP-2537 format
 * EIP-2537 format: 256 bytes = 64 bytes x_im || 64 bytes x_re || 64 bytes y_im || 64 bytes y_re
 * 
 * Uses @noble/curves to properly decompress the point.
 * Note: EIP-2537 uses x_im || x_re, where:
 *   - x_re = x.c0 (real part)
 *   - x_im = x.c1 (imaginary part)
 */
export function g2SignatureToEIP2537(signature: Signature, bls: any): string {
  if (signature.length !== 96) {
    throw new Error(`Expected compressed G2 point (96 bytes), got ${signature.length} bytes`);
  }

  try {
    // Convert compressed point to hex string (no 0x prefix)
    const compressedHex = Buffer.from(signature).toString("hex");
    
    // Decompress using @noble/curves
    const point = bls.G2.ProjectivePoint.fromHex(compressedHex).toAffine();
    
    // Extract Fp2 coordinates: x = (c0, c1), y = (c0, c1)
    // Convert each component to 48-byte big-endian
    const x0 = bigintToBytesBE(point.x.c0, 48); // x real part
    const x1 = bigintToBytesBE(point.x.c1, 48); // x imaginary part
    const y0 = bigintToBytesBE(point.y.c0, 48); // y real part
    const y1 = bigintToBytesBE(point.y.c1, 48); // y imaginary part
    
    // Convert to EIP-2537 format (64 bytes each = two 32-byte limbs)
    const X0 = fp48ToEIP2537(x0); // x_re
    const X1 = fp48ToEIP2537(x1); // x_im
    const Y0 = fp48ToEIP2537(y0); // y_re
    const Y1 = fp48ToEIP2537(y1); // y_im
    
    const result = Buffer.concat([X0.hi, X0.lo, X1.hi, X1.lo, Y0.hi, Y0.lo, Y1.hi, Y1.lo]);
    
    return "0x" + result.toString("hex");
  } catch (error: any) {
    throw new Error(`Failed to decompress G2 point: ${error.message}`);
  }
}

/**
 * Use the contract's precompiles to decompress a G1 point
 * This requires calling the MAP_FP_TO_G1 precompile (0x10)
 */
export async function decompressG1UsingPrecompile(
  provider: ethers.Provider,
  compressed: Buffer
): Promise<string> {
  // This would use the EIP-2537 precompile directly
  // For now, return a placeholder
  throw new Error("Not implemented - requires direct precompile call");
}

/**
 * Use the contract's precompiles to decompress a G2 point
 * This requires calling the MAP_FP2_TO_G2 precompile (0x11)
 */
export async function decompressG2UsingPrecompile(
  provider: ethers.Provider,
  compressed: Buffer
): Promise<string> {
  // This would use the EIP-2537 precompile directly
  // For now, return a placeholder
  throw new Error("Not implemented - requires direct precompile call");
}

/**
 * Standard DST for BLS signatures
 */
export const BLS_SIG_DST = Buffer.from(
  "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_",
  "utf-8"
);

/**
 * Convert DST buffer to hex string for contract calls
 * Returns a hex string that can be used directly as bytes calldata
 */
export function dstToHexArray(dst: Buffer): string {
  return ethers.hexlify(new Uint8Array(dst));
}

/**
 * Convert DST buffer to Uint8Array for contract calls
 * Alternative method if you prefer Uint8Array
 */
export function dstToBytes(dst: Buffer): Uint8Array {
  return new Uint8Array(dst);
}

/**
 * Verify that a BLS signature is valid using the contract
 * This is a helper that handles format conversion
 */
export async function verifyBLSOnChain(
  contract: ethers.Contract,
  privateKey: PrivateKey,
  message: string,
  bls: any,
  dst: Buffer = BLS_SIG_DST
): Promise<boolean> {
  const messageBytes = new TextEncoder().encode(message);
  
  // Get public key and sign using @noble/curves
  const publicKey = bls.getPublicKey(privateKey);
  const signature = bls.sign(messageBytes, privateKey);
  
  // Convert to EIP-2537 format
  const pkG1 = g1PublicKeyToEIP2537(publicKey, bls);
  const sigG2 = g2SignatureToEIP2537(signature, bls);
  
  // Call contract
  try {
    const isValid = await contract.verifyWithHashToCurveG2(
      pkG1,
      sigG2,
      ethers.toUtf8Bytes(message),
      dstToHexArray(dst)
    );
    return isValid;
  } catch (error: any) {
    console.error("Contract verification failed:", error.message);
    throw error;
  }
}
