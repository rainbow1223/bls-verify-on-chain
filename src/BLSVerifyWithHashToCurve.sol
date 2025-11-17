// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
    Combined on-chain BLS12-381 verifier with hash_to_curve(G2, XMD:SHA-256, SSWU, RO) and pairing.
    Uses EIP-2537 precompiles.

    Precompile addresses (as used below):
      0x0a: G1 ADD
      0x0d: G2 ADD
      0x0f: PAIRING
      0x11: MAP_FP_TO_G1
      0x12: MAP_FP2_TO_G2

    Point encodings follow EIP-2537:
      - Fp element: 64-byte big-endian
      - G1 point: 128 bytes = X(64) || Y(64)
      - G2 point: 256 bytes = X_im(64) || X_re(64) || Y_im(64) || Y_re(64)
*/

struct FieldPoint { bytes32[2] u; }                 // Fp element split into two 32B words
struct FieldPoint2 { bytes32[2] u; bytes32[2] u_I; } // Fp2 element: u + u_I*i  (each as two 32B words)

struct G1Point { bytes x; bytes y; }                 // each 64B
struct G2Point { bytes x; bytes x_I; bytes y; bytes y_I; } // each 64B

library BLSPrecompiles {
    uint256 constant G1_ADD             = 0x0b;
    uint256 constant G2_ADD             = 0x0d;
    uint256 constant PAIRING            = 0x0f;
    uint256 constant MAP_FP_TO_G1       = 0x10;
    uint256 constant MAP_FP2_TO_G2      = 0x11;

    function pairing(bytes memory input) internal view returns (bool) {
        bytes memory out32 = new bytes(32);
        bool ok;
        assembly {
            ok := staticcall(gas(), PAIRING, add(input, 0x20), mload(input), add(out32, 0x20), 32)
        }
        if (!ok) return false;
        return out32[31] == 0x01;
    }
}

contract BLSVerifyWithHashToCurve {
    using BLSPrecompiles for bytes;

    // -G1 generator in uncompressed EIP-2537 encoding (x||y_neg), 64B each
    bytes constant NEG_G1_GENERATOR = hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb00000000000000000000000000000000114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca";
    /* =========================
       Public entry points
       ========================= */

    /// Verify BLS signature with on-chain hash_to_curve (G2).
    /// Inputs are UNCOMPRESSED EIP-2537 encodings for pk and sig.
    function verifyWithHashToCurveG2(
        bytes calldata pkG1_128,     // 128B (x||y)
        bytes calldata sigG2_256,     // 256B (x_im||x_re||y_im||y_re)
        bytes calldata msg_,          // arbitrary
        bytes calldata dst            // ≤ 255 bytes
    ) external view returns (bool) {
        require(pkG1_128.length == 128, "pkG1 must be 128B");
        require(sigG2_256.length == 256, "sigG2 must be 256B");

        // H(msg, dst) in G2 (uncompressed 256B)
        G2Point memory H = hashToCurveG2(msg_, dst);
        bytes memory H_bytes = _packG2(H);

        // e(-G1, sig) * e(pk, H(msg)) == 1
        bytes memory input = abi.encodePacked(NEG_G1_GENERATOR, sigG2_256, pkG1_128, H_bytes);
        return BLSPrecompiles.pairing(input);
    }

    function hashToCurve(bytes calldata message, bytes calldata dst) public view returns (bytes memory) {
        G2Point memory H = hashToCurveG2(message, dst);
        return _packG2(H);
    }

    /// Expose hash_to_curve for G2 (handy for testing)
    function hashToCurveG2(
        bytes calldata message,
        bytes calldata dst
    ) public view returns (G2Point memory) {
        // 1) u = hash_to_field(msg, count=2), m=2 for Fp2
        FieldPoint2[2] memory u = hashToFieldFp2(message, dst);
        // 2) Q0 = map_to_curve(u[0])
        bytes32[8] memory q0 = _mapFp2ToG2(u[0]);
        // 3) Q1 = map_to_curve(u[1])
        bytes32[8] memory q1 = _mapFp2ToG2(u[1]);
        // 4) R = Q0 + Q1
        bytes32[8] memory r = _addG2(q0, q1);
        // 5) Clear cofactor: per EIP-2537 map precompile, the result is already on the correct subgroup.
        // 6) Return as structured bytes
        return G2Point({
            x:   bytes.concat(r[0], r[1]),   // X_im || X_re (each 32B -> total 64B)
            x_I: bytes.concat(r[2], r[3]),
            y:   bytes.concat(r[4], r[5]),
            y_I: bytes.concat(r[6], r[7])
        });
    }

    /* =========================
       hash_to_field (RFC 9380 §5.2) with XMD:SHA-256
       ========================= */

    function hashToFieldFp2(
        bytes calldata message,
        bytes calldata dst
    ) public view returns (FieldPoint2[2] memory) {
        // len_in_bytes = count * m * L = 2 * 2 * 64 = 256
        uint16 lenInBytes = 256;
        bytes32[] memory prb = expandMsgXmd(message, dst, lenInBytes);
        FieldPoint2[2] memory u;

        // e_0 = OS2IP(tv0) mod p, etc. (we store as two 32B words big-endian)
        u[0].u   = _modfield(prb[0], prb[1]);
        u[0].u_I = _modfield(prb[2], prb[3]);
        u[1].u   = _modfield(prb[4], prb[5]);
        u[1].u_I = _modfield(prb[6], prb[7]);
        return u;
    }

    // XMD:SHA-256 (RFC 9380 §5.3), returning 32-byte chunks
    function expandMsgXmd(
        bytes calldata message,
        bytes calldata dst,
        uint16 lenInBytes
    ) public pure returns (bytes32[] memory) {
        // ell = ceil(len_in_bytes / 32)
        uint ell = (lenInBytes - 1) / 32 + 1;
        require(ell <= 255, "len too large for SHA-256");
        require(dst.length <= 255, "dst too long");

        // DST' = DST || len(DST)
        bytes memory dstPrime = bytes.concat(dst, bytes1(uint8(dst.length)));

        // Z_pad = I2OSP(0, 64)
        bytes32 zPad1 = 0x0;
        bytes32 zPad2 = 0x0;

        // l_i_b_str = I2OSP(len_in_bytes, 2)
        bytes2 libStr = bytes2(lenInBytes);

        // msg' = Z_pad || msg || l_i_b_str || I2OSP(0,1) || DST'
        bytes memory msgPrime = bytes.concat(zPad1, zPad2, message, libStr, hex"00", dstPrime);

        bytes32 b0 = sha256(msgPrime);
        bytes32[] memory b = new bytes32[](ell);

        // b_1 = H(b0 || 0x01 || DST')
        b[0] = sha256(bytes.concat(b0, hex"01", dstPrime));

        // b_i = H( (b0 XOR b_{i-1}) || I2OSP(i,1) || DST' )
        for (uint8 i = 2; i <= ell; i++) {
            b[i - 1] = sha256(abi.encodePacked(b0 ^ b[i - 2], i, dstPrime));
        }
        return b; // caller slices as needed in 32B chunks
    }

    /* =========================
       EIP-2537 helpers
       ========================= */

    // Fp reduce OS2IP(tv) mod p, tv provided as two 32B limbs (total 64B big-endian)
    function _modfield(bytes32 _b1, bytes32 _b2) internal view returns (bytes32[2] memory r) {
        assembly {
            let bl := 0x40
            let ml := 0x40
            let freemem := mload(0x40)

            mstore(freemem, bl)                 // base.length
            mstore(add(freemem, 0x20), 0x20)    // exp.length
            mstore(add(freemem, 0x40), ml)      // mod.length

            mstore(add(freemem, 0x60), _b1)     // base (first 32B)
            mstore(add(freemem, 0x80), _b2)     // base (last 32B)
            mstore(add(freemem, 0xa0), 1)       // exponent = 1

            // p (BLS12-381 Fp), padded to 64B
            mstore(add(freemem, 0xc0), 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7)
            mstore(add(freemem, 0xe0), 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)

            let success := staticcall(sub(gas(), 1350), 0x05, freemem, 0x100, freemem, ml)
            switch success case 0 { invalid() }

            r := freemem
            mstore(0x40, add(freemem, ml))
        }
    }

    function _mapFp2ToG2(FieldPoint2 memory fp2) internal view returns (bytes32[8] memory result) {
        bytes32[4] memory input;
        input[0] = fp2.u[0];
        input[1] = fp2.u[1];
        input[2] = fp2.u_I[0];
        input[3] = fp2.u_I[1];

        bool success;
        assembly {
            success := staticcall(gas(), 0x11, input, 128, result, 256)
        }

        if (!success) revert("EIP-2537: MAP_FP2_TO_G2 missing");

        // Detect networks where precompile returns success but outputs all-zero (i.e., unimplemented)
        bool isZero = true;
        for (uint i = 0; i < 8; i++) {
            if (result[i] != 0) { isZero = false; break; }
        }
        if (isZero) revert("EIP-2537: MAP_FP2_TO_G2 not implemented");

        return result;
    }

    function _addG2(bytes32[8] memory p1, bytes32[8] memory p2) internal view returns (bytes32[8] memory result) {
        bytes32[16] memory input;
        input[0]=p1[0]; input[1]=p1[1]; input[2]=p1[2]; input[3]=p1[3];
        input[4]=p1[4]; input[5]=p1[5]; input[6]=p1[6]; input[7]=p1[7];
        input[8]=p2[0]; input[9]=p2[1]; input[10]=p2[2]; input[11]=p2[3];
        input[12]=p2[4]; input[13]=p2[5]; input[14]=p2[6]; input[15]=p2[7];

        bool success;
        assembly {
            success := staticcall(gas(), 0x0d, input, 512, result, 256)
        }

        if (!success) revert("EIP-2537: G2_ADD missing");

        bool isZero = true;
        for (uint i = 0; i < 8; i++) {
            if (result[i] != 0) { isZero = false; break; }
        }
        if (isZero) revert("EIP-2537: G2_ADD not implemented");

        return result;
    }

    /* =========================
       Packing helpers
       ========================= */

    function _packG2(G2Point memory P) internal pure returns (bytes memory) {
        // EIP-2537 G2 encoding order:
        //   X_im || X_re || Y_im || Y_re  (each 64 bytes)
        // Here P.x = X (re), P.x_I = X (im) — keep ordering per EIP-2537!
        // If your mapper already outputs in that order, use accordingly.
        return abi.encodePacked(P.x, P.x_I, P.y, P.y_I);
    }
}
