package org.outerssh;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.*;

public final class AndroidCrypto {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final byte[] EMPTY = new byte[0];
    private static final BigInteger ZERO = BigInteger.ZERO;
    private static final class SSHKey {
        final int kind;
        final PublicKey publicKey;
        final PrivateKey privateKey;
        SSHKey(int kind, PublicKey publicKey, PrivateKey privateKey) {
            this.kind = kind; this.publicKey = publicKey; this.privateKey = privateKey;
        }
    }
    private static final class PacketKey {
        final SecretKeySpec key;
        final Cipher cipher;
        PacketKey(byte[] bytes) throws GeneralSecurityException {
            key = new SecretKeySpec(bytes, "AES"); cipher = Cipher.getInstance("AES/GCM/NoPadding");
        }
    }
    private static String hash(int length) {
        switch(length) {
            case 20: return "SHA-1";
            case 32: return "SHA-256";
            case 48: return "SHA-384";
            case 64: return "SHA-512";
            default: throw new IllegalArgumentException("Unsupported digest");
        }
    }
    private static ECParameterSpec parameters(int kind) throws GeneralSecurityException {
        if(kind != 256 && kind != 384 && kind != 521) throw new InvalidKeyException("Unsupported EC curve");
        AlgorithmParameters p = AlgorithmParameters.getInstance("EC");
        p.init(new ECGenParameterSpec("secp" + kind + "r1"));
        return p.getParameterSpec(ECParameterSpec.class);
    }
    private static byte[] fixed(BigInteger number, int length) {
        if(number.signum() < 0 || number.bitLength() > length * 8) throw new IllegalArgumentException("Invalid integer");
        byte[] bytes = number.toByteArray(), out = new byte[length];
        int count = Math.min(bytes.length, length);
        System.arraycopy(bytes, bytes.length - count, out, length - count, count);
        return out;
    }
    private static byte[] point(ECPublicKey key) {
        int size = (key.getParams().getCurve().getField().getFieldSize() + 7) / 8;
        return concat(new byte[]{4}, fixed(key.getW().getAffineX(), size), fixed(key.getW().getAffineY(), size));
    }
    private static PublicKey ecPublic(int kind, byte[] bytes) throws GeneralSecurityException {
        int size = (kind + 7) / 8;
        if(bytes.length != 1 + size * 2 || bytes[0] != 4) throw new InvalidKeyException("Invalid EC public key");
        ECPoint point = new ECPoint(new BigInteger(1, Arrays.copyOfRange(bytes, 1, 1 + size)),
            new BigInteger(1, Arrays.copyOfRange(bytes, 1 + size, bytes.length)));
        ECParameterSpec params = parameters(kind);
        BigInteger p = ((ECFieldFp)params.getCurve().getField()).getP();
        BigInteger x = point.getAffineX(), y = point.getAffineY();
        if(x.compareTo(p) >= 0 || y.compareTo(p) >= 0 || !y.multiply(y).mod(p).equals(
            x.multiply(x).multiply(x).add(params.getCurve().getA().multiply(x)).add(params.getCurve().getB()).mod(p)))
            throw new InvalidKeyException("EC point is not on curve");
        return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, params));
    }
    private static byte[] edAlgorithm() { return der(48, der(6, new byte[]{43, 101, 112})); }
    private static PublicKey edPublic(byte[] bytes) throws GeneralSecurityException {
        if(bytes.length != 32) throw new InvalidKeyException("Invalid Ed25519 public key");
        return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(
            der(48, concat(edAlgorithm(), der(3, concat(new byte[]{0}, bytes))))));
    }
    public static Object create(int operation, int kind, byte[] a, byte[] b) throws GeneralSecurityException {
        switch(operation) {
            case 1: return MessageDigest.getInstance(hash(kind));
            case 2: {
                Mac mac = Mac.getInstance("Hmac" + hash(kind).replace("-", ""));
                mac.init(new SecretKeySpec(a, mac.getAlgorithm())); return mac;
            }
            case 3: {
                Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
                cipher.init(kind != 0 ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, new SecretKeySpec(a, "AES"), new IvParameterSpec(b));
                return cipher;
            }
            case 4: return new SSHKey(kind, kind == 1 ? edPublic(a) : ecPublic(kind, a), null);
            case 5: return new SSHKey(0, KeyFactory.getInstance("RSA").generatePublic(
                new RSAPublicKeySpec(new BigInteger(1, b), new BigInteger(1, a))), null);
            case 6: return parsePrivate(a);
            case 7: return new PacketKey(a);
            default: throw new IllegalArgumentException("Unknown crypto operation");
        }
    }
    public static byte[] run(int operation, int kind, Object context, byte[] a, byte[] b, byte[] c) throws GeneralSecurityException {
        switch(operation) {
            case 1:
                if(context instanceof Mac) ((Mac)context).update(a); else ((MessageDigest)context).update(a);
                return EMPTY;
            case 2: return context instanceof Mac ? ((Mac)context).doFinal() : ((MessageDigest)context).digest();
            case 3: { byte[] out = ((Cipher)context).update(a); return out == null ? EMPTY : out; }
            case 4: { byte[] out = new byte[kind]; RANDOM.nextBytes(out); return out; }
            case 5: return MessageDigest.getInstance(hash(kind)).digest(a);
            case 6: return ByteBuffer.allocate(4).putInt(((SSHKey)context).kind).array();
            case 7: return publicBlob((SSHKey)context);
            case 8: return sign((SSHKey)context, a);
            case 9: {
                Signature signature = Signature.getInstance(((SSHKey)context).kind == 1 ? "Ed25519" : hash(kind).replace("-", "") + "withRSA");
                signature.initVerify(((SSHKey)context).publicKey); signature.update(b);
                if(!signature.verify(a)) throw new SignatureException("Invalid SSH signature");
                return EMPTY;
            }
            case 10: {
                SSHKey key = (SSHKey)context;
                Signature signature = Signature.getInstance("SHA" + (key.kind == 521 ? 512 : key.kind) + "withECDSA");
                signature.initVerify(key.publicKey); signature.update(c);
                if(!signature.verify(der(48, concat(derInteger(a), derInteger(b))))) throw new SignatureException("Invalid ECDSA signature");
                return EMPTY;
            }
            case 11: {
                KeyPairGenerator generator = KeyPairGenerator.getInstance(kind == 1 ? "XDH" : "EC");
                if(kind == 1) generator.initialize(255, RANDOM);
                else generator.initialize(new ECGenParameterSpec("secp" + kind + "r1"), RANDOM);
                KeyPair pair = generator.generateKeyPair();
                if(kind != 1) return concat(fixed(((ECPrivateKey)pair.getPrivate()).getS(), (kind + 7) / 8), point((ECPublicKey)pair.getPublic()));
                Reader priv = new Reader(new Reader(pair.getPrivate().getEncoded()).der(48));
                priv.der(2); priv.der(48);
                byte[] scalar = new Reader(priv.der(4)).der(4);
                Reader pub = new Reader(new Reader(pair.getPublic().getEncoded()).der(48));
                pub.der(48); byte[] bits = pub.der(3);
                if(scalar.length != 32 || bits.length != 33 || bits[0] != 0) throw new InvalidKeyException("Unexpected X25519 encoding");
                return concat(scalar, Arrays.copyOfRange(bits, 1, 33));
            }
            case 12: {
                KeyFactory factory = KeyFactory.getInstance(kind == 1 ? "XDH" : "EC");
                PrivateKey priv;
                PublicKey pub;
                if(kind == 1) {
                    if(a.length != 32 || b.length != 32) throw new InvalidKeyException("Invalid X25519 key");
                    byte[] algorithm = der(48, der(6, new byte[]{43, 101, 110}));
                    priv = factory.generatePrivate(new PKCS8EncodedKeySpec(der(48, concat(der(2, new byte[]{0}), algorithm, der(4, der(4, a))))));
                    pub = factory.generatePublic(new X509EncodedKeySpec(der(48, concat(algorithm, der(3, concat(new byte[]{0}, b))))));
                } else {
                    priv = factory.generatePrivate(new ECPrivateKeySpec(new BigInteger(1, a), parameters(kind)));
                    pub = ecPublic(kind, b);
                }
                KeyAgreement agreement = KeyAgreement.getInstance(kind == 1 ? "XDH" : "ECDH");
                agreement.init(priv); agreement.doPhase(pub, true); byte[] shared = agreement.generateSecret();
                int nonzero = 0; for(byte value : shared) nonzero |= value;
                if(nonzero == 0) throw new InvalidKeyException("Invalid all-zero shared secret");
                return shared;
            }
            case 13: {
                if(a.length != 12 || b.length < (kind != 0 ? 4 : 20)) throw new IllegalArgumentException("Invalid SSH packet");
                PacketKey key = (PacketKey)context;
                key.cipher.init(kind != 0 ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, key.key, new GCMParameterSpec(128, a));
                key.cipher.updateAAD(b, 0, 4);
                return concat(Arrays.copyOf(b, 4), key.cipher.doFinal(b, 4, b.length - 4));
            }
            case 14: {
                byte[][] identity = generateIdentity();
                try { return concat(ssh(identity[0]), ssh(identity[1]), ssh(identity[2])); }
                finally { Arrays.fill(identity[0], (byte)0); }
            }
            case 15: return pairingCrypt(a, b, new String(c, StandardCharsets.US_ASCII), kind != 0);
            case 16: return (kind != 0 ? Base64.getUrlEncoder().withoutPadding() : Base64.getEncoder()).encode(a);
            default: throw new IllegalArgumentException("Unknown crypto operation");
        }
    }
    private static byte[] sign(SSHKey key, byte[] digest) throws GeneralSecurityException {
        Signature signature = Signature.getInstance(key.kind == 1 ? "Ed25519" : key.kind == 0 ? "NONEwithRSA" : "NONEwithECDSA");
        signature.initSign(key.privateKey);
        if(key.kind == 1) {
            signature.update(digest);
            return signature.sign();
        }
        if(key.kind == 0) {
            byte[] oid;
            if(digest.length == 32) oid = new byte[]{96, -122, 72, 1, 101, 3, 4, 2, 1};
            else if(digest.length == 64) oid = new byte[]{96, -122, 72, 1, 101, 3, 4, 2, 3};
            else throw new SignatureException("Unsupported RSA digest");
            signature.update(der(48, concat(der(48, concat(der(6, oid), der(5, EMPTY))), der(4, digest))));
            return signature.sign();
        }
        int expected = key.kind == 521 ? 64 : key.kind / 8;
        if(digest.length != expected) throw new SignatureException("Invalid ECDSA digest");
        signature.update(digest);
        Reader encoded = new Reader(new Reader(signature.sign()).der(48));
        byte[] r = encoded.der(2), s = encoded.der(2); encoded.end();
        return concat(ssh(new BigInteger(r).toByteArray()), ssh(new BigInteger(s).toByteArray()));
    }
    private static byte[] publicBlob(SSHKey key) {
        if(key.kind == 1) {
            Reader encoded = new Reader(new Reader(key.publicKey.getEncoded()).der(48));
            encoded.der(48);
            byte[] bits = encoded.der(3);
            if(bits.length != 33 || bits[0] != 0) throw new IllegalArgumentException("Unexpected Ed25519 encoding");
            return concat(ssh("ssh-ed25519"), ssh(Arrays.copyOfRange(bits, 1, 33)));
        }
        if(key.kind == 0) {
            RSAPublicKey rsa = (RSAPublicKey)key.publicKey;
            return concat(ssh("ssh-rsa"), ssh(rsa.getPublicExponent().toByteArray()), ssh(rsa.getModulus().toByteArray()));
        }
        return concat(ssh("ecdsa-sha2-nistp" + key.kind), ssh("nistp" + key.kind), ssh(point((ECPublicKey)key.publicKey)));
    }
    private static SSHKey parsePrivate(byte[] pem) throws GeneralSecurityException {
        if(pem.length > 1024 * 1024) throw new InvalidKeyException("Key is too large");
        String text = new String(pem, StandardCharsets.US_ASCII).trim();
        String begin = "-----BEGIN OPENSSH PRIVATE KEY-----", end = "-----END OPENSSH PRIVATE KEY-----";
        if(!text.startsWith(begin) || !text.endsWith(end)) throw new InvalidKeyException("Expected an unencrypted OpenSSH RSA, ECDSA, or Ed25519 private key");
        byte[] decoded = Base64.getDecoder().decode(text.substring(begin.length(), text.length() - end.length()).replaceAll("\\s", ""));
        try {
            Reader file = new Reader(decoded);
            if(!Arrays.equals(file.take(15), "openssh-key-v1\0".getBytes(StandardCharsets.US_ASCII))) throw new InvalidKeyException("Invalid key header");
            if(!file.text().equals("none") || !file.text().equals("none") || file.string().length != 0 || file.integer() != 1)
                throw new InvalidKeyException("Encrypted or multi-key OpenSSH files are unsupported");
            byte[] publicBytes = file.string();
            byte[] privateBytes = file.string(); file.end();
            try {
                Reader data = new Reader(privateBytes);
                if(data.integer() != data.integer()) throw new InvalidKeyException("Invalid key check value");
                String type = data.text(); SSHKey result;
                if(type.equals("ssh-ed25519")) {
                    byte[] pub = data.string(), secret = data.string();
                    try {
                        if(pub.length != 32 || secret.length != 64 || !Arrays.equals(pub, Arrays.copyOfRange(secret, 32, 64)))
                            throw new InvalidKeyException("Invalid Ed25519 private key");
                        byte[] encoded = der(48, concat(der(2, new byte[]{0}), edAlgorithm(), der(4, der(4, Arrays.copyOf(secret, 32)))));
                        try {
                            result = new SSHKey(1, edPublic(pub), KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(encoded)));
                        } finally { Arrays.fill(encoded, (byte)0); }
                    } finally { Arrays.fill(secret, (byte)0); }
                } else if(type.equals("ssh-rsa")) {
                    BigInteger n = data.mpint(), e = data.mpint(), d = data.mpint(), iq = data.mpint(), p = data.mpint(), q = data.mpint();
                    if(!p.multiply(q).equals(n) || !q.modInverse(p).equals(iq)) throw new InvalidKeyException("Invalid RSA private key");
                    KeyFactory factory = KeyFactory.getInstance("RSA");
                    result = new SSHKey(0, factory.generatePublic(new RSAPublicKeySpec(n, e)), factory.generatePrivate(
                        new RSAPrivateCrtKeySpec(n, e, d, p, q, d.mod(p.subtract(BigInteger.ONE)), d.mod(q.subtract(BigInteger.ONE)), iq)));
                } else {
                    int kind = type.equals("ecdsa-sha2-nistp256") ? 256 : type.equals("ecdsa-sha2-nistp384") ? 384 : type.equals("ecdsa-sha2-nistp521") ? 521 : 0;
                    if(kind == 0 || !data.text().equals("nistp" + kind)) throw new InvalidKeyException("Unsupported private-key algorithm");
                    PublicKey pub = ecPublic(kind, data.string()); BigInteger scalar = data.mpint(); ECParameterSpec params = parameters(kind);
                    if(scalar.compareTo(params.getOrder()) >= 0) throw new InvalidKeyException("Invalid EC scalar");
                    result = new SSHKey(kind, pub, KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(scalar, params)));
                }
                data.string();
                int padding = 1;
                while(data.remaining() > 0) if((data.take(1)[0] & 255) != padding++) throw new InvalidKeyException("Invalid key padding");
                if(padding > 9 || !Arrays.equals(publicBytes, publicBlob(result))) throw new InvalidKeyException("Public key mismatch");
                Signature proof = Signature.getInstance(result.kind == 1 ? "Ed25519" : result.kind == 0 ? "SHA256withRSA" : "SHA256withECDSA");
                proof.initSign(result.privateKey); proof.update(publicBytes); byte[] sig = proof.sign();
                proof.initVerify(result.publicKey); proof.update(publicBytes);
                if(!proof.verify(sig)) throw new InvalidKeyException("Private key mismatch");
                return result;
            } finally { Arrays.fill(privateBytes, (byte)0); }
        } finally { Arrays.fill(decoded, (byte)0); }
    }
    public static byte[][] generateIdentity() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC"); generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair pair = generator.generateKeyPair(); SSHKey key = new SSHKey(256, pair.getPublic(), pair.getPrivate());
        byte[] pub = publicBlob(key), check = new byte[4]; RANDOM.nextBytes(check);
        byte[] section = concat(check, check, ssh("ecdsa-sha2-nistp256"), ssh("nistp256"), ssh(point((ECPublicKey)pair.getPublic())),
            ssh(((ECPrivateKey)pair.getPrivate()).getS().toByteArray()), ssh("outer-loop-android"));
        byte[] padding = new byte[8 - section.length % 8]; for(int i = 0; i < padding.length; i++) padding[i] = (byte)(i + 1);
        byte[] privateBytes = concat(section, padding);
        byte[] encoded = concat("openssh-key-v1\0".getBytes(StandardCharsets.US_ASCII), ssh("none"), ssh("none"), ssh(EMPTY),
            ByteBuffer.allocate(4).putInt(1).array(), ssh(pub), ssh(privateBytes));
        try {
            String pem = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + Base64.getMimeEncoder(64, new byte[]{10}).encodeToString(encoded) + "\n-----END OPENSSH PRIVATE KEY-----\n";
            return new byte[][] {pem.getBytes(StandardCharsets.US_ASCII),
                ("ecdsa-sha2-nistp256 " + Base64.getEncoder().encodeToString(pub) + " outer-loop-android").getBytes(StandardCharsets.US_ASCII),
                ("SHA256:" + Base64.getEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(pub))).getBytes(StandardCharsets.US_ASCII)};
        } finally { Arrays.fill(section, (byte)0); Arrays.fill(privateBytes, (byte)0); Arrays.fill(encoded, (byte)0); }
    }
    public static byte[] pairingCrypt(byte[] input, byte[] key, String identifier, boolean seal) throws GeneralSecurityException {
        if(key.length != 32 || !identifier.matches("[A-Za-z0-9_-]{24}") ||
            (seal ? input.length > 65408 : input.length < 28 || input.length > 65536)) throw new IllegalArgumentException("Invalid pairing message");
        byte[] nonce = seal ? new byte[12] : Arrays.copyOf(input, 12); if(seal) RANDOM.nextBytes(nonce);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(seal ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD(("outerloop-access-pairing-v2:" + identifier).getBytes(StandardCharsets.US_ASCII));
        byte[] result = cipher.doFinal(input, seal ? 0 : 12, input.length - (seal ? 0 : 12));
        return seal ? concat(nonce, result) : result;
    }
    static byte[] concat(byte[]... values) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for(byte[] value : values) out.write(value, 0, value.length);
        return out.toByteArray();
    }
    static byte[] ssh(String value) { return ssh(value.getBytes(StandardCharsets.US_ASCII)); }
    static byte[] ssh(byte[] value) { return concat(ByteBuffer.allocate(4).putInt(value.length).array(), value); }
    static byte[] der(int tag, byte[] value) {
        int length = value.length;
        byte[] size = length < 128 ? new byte[]{(byte)length} : length < 256 ? new byte[]{(byte)129, (byte)length} : new byte[]{(byte)130, (byte)(length >> 8), (byte)length};
        if(length > 65535) throw new IllegalArgumentException("DER value too large");
        return concat(new byte[]{(byte)tag}, size, value);
    }
    private static byte[] derInteger(byte[] value) { return der(2, new BigInteger(1, value).toByteArray()); }
    private static final class Reader {
        final byte[] bytes; int position;
        Reader(byte[] bytes) { this.bytes = bytes; }
        int remaining() { return bytes.length - position; }
        byte[] take(int count) {
            if(count < 0 || count > remaining()) throw new IllegalArgumentException("Truncated key");
            byte[] result = Arrays.copyOfRange(bytes, position, position + count); position += count; return result;
        }
        int integer() { return ByteBuffer.wrap(take(4)).getInt(); }
        byte[] string() { return take(integer()); }
        String text() { return new String(string(), StandardCharsets.US_ASCII); }
        BigInteger mpint() {
            byte[] value = string();
            if(value.length == 0 || value.length > 2049) throw new IllegalArgumentException("Invalid key integer");
            BigInteger integer = new BigInteger(value);
            if(integer.compareTo(ZERO) <= 0) throw new IllegalArgumentException("Invalid key integer");
            return integer;
        }
        byte[] der(int tag) {
            if((take(1)[0] & 255) != tag) throw new IllegalArgumentException("Invalid DER tag");
            int length = take(1)[0] & 255;
            if(length > 127) {
                int count = length & 127;
                if(count == 0 || count > 3) throw new IllegalArgumentException("Invalid DER length");
                length = 0; for(byte value : take(count)) length = (length << 8) | (value & 255);
            }
            return take(length);
        }
        void end() { if(remaining() != 0) throw new IllegalArgumentException("Trailing key data"); }
    }
}
