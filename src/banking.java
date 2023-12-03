import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;

import javax.crypto.spec.SecretKeySpec;


import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryUsage;


import java.lang.management.ManagementFactory;
import com.sun.management.OperatingSystemMXBean;

public class banking {

    private static final String RSA_ALGORITHM = "RSA";
    private static final String AES_ALGORITHM = "AES";
    private static final String RSA_CIPHER_ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String AES_CIPHER_ALGORITHM = "AES/GCM/NoPadding";
    private static final String DIGEST_ALGORITHM = "SHA-256";

    //This method generates a new RSA key pair with 4096-bit key length.
    // It uses a secure random number generator to create a random seed for the key pair generator.
    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        generator.initialize(4096, random);
        KeyPair pair = generator.generateKeyPair();
        return pair;
    }

    //This method generates a new AES key with 256-bit key length.
    //It uses a secure random number generator to create a random seed for the key generator.
    private static Key generateAESKey() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance(AES_ALGORITHM);
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        generator.init(256, random);
        Key key = generator.generateKey();
        return key;
    }


    //This method generates a new RSA key pair with 2048-bit key length.
    //It is used for generating digital signatures.
    //as the private key in the key pair can be used to sign data and the public key can be used to verify the digital signature.
    private static KeyPair generateSignatureKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        return pair;
    }

    //This method generates a digital signature for a given data using a private RSA key.
    //It uses the SHA256withRSA algorithm to sign the data.
    private static byte[] generateDigitalSignature(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        byte[] signatureBytes = signature.sign();
        return signatureBytes;
    }

    //This method takes in three parameters: data (the original data), signatureBytes (the signature of the data), and publicKey (the public key of the signer).
    //It verifies the digital signature of the data by initializing a Signature instance with the "SHA256withRSA" algorithm,
    //setting the instance to verification mode using the public key, and then updating the instance with the original data.
    //Finally, it returns a boolean value indicating whether the signature is valid.
    private static boolean verifyDigitalSignature(byte[] data, byte[] signatureBytes, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }

    //It encrypts the data using the RSA algorithm by initializing a Cipher instance with the RSA_CIPHER_ALGORITHM,
    //setting the instance to encryption mode using the public key, and then encrypting the data with the doFinal() method.
    //Finally, it returns the encrypted data as a byte array.
    private static byte[] encryptWithRSA(byte[] data, Key publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedData = cipher.doFinal(data);
        return encryptedData;
    }

    //It decrypts the encrypted data using the RSA algorithm by initializing a Cipher instance with the RSA_CIPHER_ALGORITHM,
    //setting the instance to decryption mode using the private key, and then decrypting the data with the doFinal() method.
    //Finally, it returns the decrypted data as a byte array.
    private static byte[] decryptWithRSA(byte[] encryptedData, Key privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedData = cipher.doFinal(encryptedData);
        return decryptedData;
    }


    //It encrypts the data using the AES algorithm by initializing a Cipher instance with the AES_CIPHER_ALGORITHM, generating a 96-bit IV (Initialization Vector) using a SecureRandom instance,
    //setting the instance to encryption mode using the key and IV, and then encrypting the data with the doFinal() method.
    // Finally, it returns the encrypted data as a byte array with the IV appended to the beginning of the array.
    private static byte[] encryptWithAES(byte[] data, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[12]; // 96-bit IV
        random.nextBytes(iv);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        byte[] encryptedData = cipher.doFinal(data);
        byte[] result = new byte[iv.length + encryptedData.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(encryptedData, 0, result, iv.length, encryptedData.length);
        return result;
    }

    //It decrypts the encrypted data using the AES algorithm by initializing a Cipher instance with the AES_CIPHER_ALGORITHM, extracting the IV from the beginning of the encrypted data,
    // setting the instance to decryption mode using the key and IV, and then decrypting the data with the doFinal() method.
    // Finally, it returns the decrypted data as a byte array.
    private static byte[] decryptWithAES(byte[] encryptedData, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
        byte[] iv = new byte[12]; // 96-bit IV
        System.arraycopy(encryptedData, 0, iv, 0, iv.length);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        byte[] data = new byte[encryptedData.length - iv.length];
        System.arraycopy(encryptedData, iv.length, data, 0, data.length);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        byte[] decryptedData = cipher.doFinal(data);
        return decryptedData;
    }


    //It hashes the data using the DIGEST_ALGORITHM by initializing a MessageDigest instance with the DIGEST_ALGORITHM,
    //hashing the data with the digest() method, and then returning the hashed data as a byte array.
    private static byte[] hashData(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance(DIGEST_ALGORITHM);
        byte[] hashedData = digest.digest(data);
        return hashedData;
    }

    private static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        generator.initialize(4096, random);
        KeyPair pair = generator.generateKeyPair();
        return pair;
    }


    private static void measureMemoryUsage() {
        MemoryMXBean memoryMXBean = ManagementFactory.getMemoryMXBean();
        MemoryUsage heapMemoryUsage = memoryMXBean.getHeapMemoryUsage();
        MemoryUsage nonHeapMemoryUsage = memoryMXBean.getNonHeapMemoryUsage();

        System.out.println("Heap Memory Usage: ");
        System.out.println("   Initial: " + (heapMemoryUsage.getInit() / (1024 * 1024)) + " MB");
        System.out.println("   Used: " + (heapMemoryUsage.getUsed() / (1024 * 1024)) + " MB");
        System.out.println("   Max: " + (heapMemoryUsage.getMax() / (1024 * 1024)) + " MB");
        System.out.println("   Committed: " + (heapMemoryUsage.getCommitted() / (1024 * 1024)) + " MB");

        System.out.println("Non-Heap Memory Usage: ");
        System.out.println("   Initial: " + (nonHeapMemoryUsage.getInit() / (1024 * 1024)) + " MB");
        System.out.println("   Used: " + (nonHeapMemoryUsage.getUsed() / (1024 * 1024)) + " MB");
        System.out.println("   Max: " + (nonHeapMemoryUsage.getMax() / (1024 * 1024)) + " MB");
        System.out.println("   Committed: " + (nonHeapMemoryUsage.getCommitted() / (1024 * 1024)) + " MB");
    }


    private static void measureCpuUsage() {
        OperatingSystemMXBean osBean = ManagementFactory.getPlatformMXBean(OperatingSystemMXBean.class);
        double cpuUsage = osBean.getProcessCpuLoad() * 100.0; // Get CPU usage as a percentage
        System.out.println("CPU Usage: " + cpuUsage + "%");
    }


    public static void main(String[] args) throws Exception {
        Scanner sc = new Scanner(System.in);

        // Measure the start time
        long startTime = System.currentTimeMillis();

        // Measure memory usage before generating RSA keys
        measureMemoryUsage();

        // Measure CPU usage before any CPU-intensive operations
        measureCpuUsage();

        // Generate a key pair for RSA encryption
        KeyPair keyPair = generateKeyPair();

        // Measure memory usage after generating RSA keys
        measureMemoryUsage();

        // Measure CPU usage after generating RSA keys
        measureCpuUsage();


        // Generate a key pair for digital signature
        KeyPair signatureKeyPair = generateSignatureKeyPair();

        // Generate a key for AES encryption
        Key aesKey = generateAESKey();

        // Encrypt the AES key with the RSA public key
        byte[] encryptedAESKey = encryptWithRSA(aesKey.getEncoded(), keyPair.getPublic());

        // Decrypt the AES key using the RSA private key using the decryptWithRSA() method
        // and create a new AES key instance using the SecretKeySpec() method.
        byte[] decryptedAESKey = decryptWithRSA(encryptedAESKey, keyPair.getPrivate());
        Key decryptedAESKeySpec = new SecretKeySpec(decryptedAESKey, "AES");

        // Read data from a file
        System.out.println("Enter the path to the file containing the original data: ");
        String filePath = sc.nextLine();
        byte[] dataBytes = Files.readAllBytes(Paths.get(filePath));

        // Encrypt the data with AES
        long encryptionStartTime = System.currentTimeMillis(); // Start measuring encryption time
        byte[] encryptedData = encryptWithAES(dataBytes, decryptedAESKeySpec);
        long encryptionEndTime = System.currentTimeMillis(); // End measuring encryption time

        // Calculate throughput for encryption
        double encryptionThroughput = calculateThroughput(dataBytes.length, encryptionEndTime - encryptionStartTime);
        System.out.println("Encryption Throughput: " + encryptionThroughput + " MB/s");

        // Tamper with the encrypted data
        // encryptedData[0] = 1;

        // Generate a digital signature of the encrypted data using the private key of the signature key pair
        byte[] signatureBytes = generateDigitalSignature(encryptedData, signatureKeyPair.getPrivate());

        // Verify the digital signature using the public key of the signature key pair
        boolean signatureVerified = verifyDigitalSignature(encryptedData, signatureBytes, signatureKeyPair.getPublic());

        // Decrypt the data with AES
        long decryptionStartTime = System.currentTimeMillis(); // Start measuring decryption time
        byte[] decryptedData = decryptWithAES(encryptedData, decryptedAESKeySpec);
        long decryptionEndTime = System.currentTimeMillis(); // End measuring decryption time

        // Calculate throughput for decryption
        double decryptionThroughput = calculateThroughput(encryptedData.length, decryptionEndTime - decryptionStartTime);
        System.out.println("Decryption Throughput: " + decryptionThroughput + " MB/s");

        String decryptedDataString = new String(decryptedData, "UTF-8");

        // Hash the decrypted data for verification
        byte[] hashedData = hashData(decryptedData);

        // Print results
        System.out.println("Original data: " + new String(dataBytes, "UTF-8"));
        System.out.println("Encrypted data: " + encryptedData);
        System.out.println("Decrypted data: " + decryptedDataString);
        System.out.println("Data hash: " + new String(hashedData, "UTF-8"));
        System.out.println("Digital signature verified: " + signatureVerified);

        // Measure memory usage before generating RSA keys
        measureMemoryUsage();

        // ... (remaining code)

        // Measure end time
        long endTime = System.currentTimeMillis();

        // Calculate total execution time
        long executionTime = endTime - startTime;
        System.out.println("Total Execution Time: " + executionTime + " ms");
    }

// ... (other methods)

    // Calculate throughput in megabytes per second (MB/s)
    private static double calculateThroughput(int dataSize, long timeMillis) {
        double dataSizeMB = dataSize / (1024.0 * 1024.0); // Convert bytes to megabytes
        double timeSeconds = timeMillis / 1000.0; // Convert milliseconds to seconds
        return dataSizeMB / timeSeconds;
    }




}