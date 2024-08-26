# SecureBankingSystem
The Secure Banking System is a Java application that demonstrates secure communication and data integrity using various cryptographic techniques. This application implements features such as RSA key pair generation, digital signature generation and verification, AES encryption and decryption, and performance measurement of memory usage and CPU usage.


Prerequisites:

Java Development Kit (JDK) 8 or later
A code editor or Integrated Development Environment (IDE) such as IntelliJ IDEA or Eclipse

Features:

RSA Key Pair Generation:

Generates a new RSA key pair with a 4096-bit key length.
AES Key Generation:

Generates a new AES key with a 256-bit key length.
Digital Signature:

Generates a digital signature for data using a private RSA key.
Verifies the digital signature using the corresponding public RSA key.
AES Encryption and Decryption:

Encrypts and decrypts data using the AES algorithm.
Memory Usage Measurement:

Measures and prints heap and non-heap memory usage.
CPU Usage Measurement:

Measures and prints CPU usage.
Performance Throughput Calculation:

Calculates and prints throughput for encryption and decryption.
Usage
Clone the repository:

bash
Copy code
git clone https://github.com/koushik007pk/SecureBankingSystem.git
Open the project in your preferred IDE.

Compile and run the banking.java file.

Follow the prompts to input the path to the file containing the original data.

Review the output, including encryption throughput, decryption throughput, and digital signature verification.

File Structure:

banking.java: The main Java file containing the Secure Banking System application.
Performance Measurement
The application includes features to measure memory usage and CPU usage before and after specific operations. The calculated throughput for encryption and decryption is also displayed.


