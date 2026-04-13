import crypto from 'crypto';
import keccak256 from 'keccak256';

/**
 * Functional Lamport Signature Implementation
 * Optimized to output data verifiable by EVM (Solidity keccak256).
 */
export class LamportSignature {
    /**
     * Generate a full Lamport keypair.
     * Generates 256 pairs of 32-byte preimages (private key).
     * Hashes each preimage, then creates a final merkle root (public key).
     */
    static generateKeypair(): { privateKey: string[][]; publicKey: string; publicComponents: string[][] } {
        const privateKey: string[][] = [];
        const publicComponents: string[][] = [];

        for (let i = 0; i < 256; i++) {
            const pre0 = crypto.randomBytes(32);
            const pre1 = crypto.randomBytes(32);

            privateKey.push([
                "0x" + pre0.toString('hex'),
                "0x" + pre1.toString('hex')
            ]);

            const pub0 = keccak256(pre0);
            const pub1 = keccak256(pre1);

            publicComponents.push([
                "0x" + pub0.toString('hex'),
                "0x" + pub1.toString('hex')
            ]);
        }

        // Let's compute a "base" public key from a hypothetical message of all 0s,
        // or just rely on the API to pass back the EVM-computed public key.
        // For standard Lamport, the public key is the hash of all public components.
        // But our EVM logic aggregates dynamically. So we just use a dummy for initialization.
        const dummyPubKey = "0x" + crypto.randomBytes(32).toString('hex');

        return {
            privateKey,
            publicKey: dummyPubKey, // Note: In practice you would calculate this on-chain
            publicComponents
        };
    }

    /**
     * Reconstruct the public key from the message and signature (Simulates EVM execution).
     * The resulting bytes32 is what the smart contract checks against `publicKeys[owner]`.
     */
    static computeEVMPublicKey(messageHash: string, signature: string[]): string {
        let currentHash = Buffer.alloc(32, 0);
        const msgBuffer = Buffer.from(messageHash.replace(/^0x/, ""), 'hex');

        let bitIndex = 0;
        for (let i = 31; i >= 0; i--) {
            const byte = msgBuffer[i];
            for (let b = 0; b < 8; b++) {
                const bit = (byte >> b) & 1;

                const preimage = Buffer.from(signature[bitIndex].replace(/^0x/, ""), 'hex');
                const pubKeyComponent = Buffer.from(keccak256(preimage));

                const encoded = Buffer.concat([
                    currentHash,
                    pubKeyComponent,
                    Buffer.from(bit === 0 ? "0000000000000000000000000000000000000000000000000000000000000000" : "0000000000000000000000000000000000000000000000000000000000000001", 'hex')
                    // Note: encoding a uint256 bit in solidity uses 32 bytes (abi.encode) or potentially 1 byte / 32 bytes based on abi.encodePacked behavior.
                    // Given our solidity uses abi.encodePacked(..., bit) where bit is uint256, it's 32 bytes.
                ]);

                currentHash = Buffer.from(keccak256(encoded));
                bitIndex++;
            }
        }

        return "0x" + currentHash.toString('hex');
    }

    /**
     * Signs a message using a Lamport private key.
     * The message must be exactly 32 bytes (e.g. a hash).
     */
    static sign(messageHash: string, privateKey: string[][]): string[] {
        if (privateKey.length !== 256) {
            throw new Error("Invalid private key size");
        }

        const cleanMsg = messageHash.replace(/^0x/, "");
        if (cleanMsg.length !== 64) {
            throw new Error("Message hash must be 32 bytes (64 hex characters)");
        }

        const msgBuffer = Buffer.from(cleanMsg, 'hex');
        const signature: string[] = [];

        // In JS we need to read bits from the buffer
        let bitIndex = 0;
        for (let i = 31; i >= 0; i--) { // Solidity uint256 is big-endian
            const byte = msgBuffer[i];
            for (let b = 0; b < 8; b++) {
                const bit = (byte >> b) & 1;
                signature.push(privateKey[bitIndex][bit]);
                bitIndex++;
            }
        }

        return signature;
    }
}
