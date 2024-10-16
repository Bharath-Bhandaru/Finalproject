#include <cstring>
#include <fstream>
#include <iostream>

// Constants used for SHA-256 algorithm
const unsigned int k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

// Macro for rotating bits to the right
#define ROTRIGHT(word,bits) (((word) >> (bits)) | ((word) << (32-(bits))))
// SHA-256 auxiliary functions
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

// SHA256 class definition for processing the hash
class SHA256 {
private:
    unsigned int state[8];   // Holds the hash state
    unsigned char data[64];  // Stores the input data
    unsigned int datalen;    // Length of the current data block
    unsigned long long bitlen; // Total number of bits processed

    // Performs the main transformation in SHA-256
    void transform() {
        unsigned int a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

        // Prepare message schedule array
        for (i = 0, j = 0; i < 16; ++i, j += 4)
            m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
        for ( ; i < 64; ++i)
            m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

        // Initialize working variables with current hash state
        a = state[0];
        b = state[1];
        c = state[2];
        d = state[3];
        e = state[4];
        f = state[5];
        g = state[6];
        h = state[7];

        // Perform the 64 rounds of hashing
        for (i = 0; i < 64; ++i) {
            t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
            t2 = EP0(a) + MAJ(a,b,c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        // Add the compressed chunk to the current hash state
        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }

public:
    // Constructor initializes the hash state
    SHA256() {
        datalen = 0;
        bitlen = 0;
        state[0] = 0x6a09e667;
        state[1] = 0xbb67ae85;
        state[2] = 0x3c6ef372;
        state[3] = 0xa54ff53a;
        state[4] = 0x510e527f;
        state[5] = 0x9b05688c;
        state[6] = 0x1f83d9ab;
        state[7] = 0x5be0cd19;
    }

    // Update function to process the input data
    void update(const unsigned char* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            this->data[datalen] = data[i];
            datalen++;
            if (datalen == 64) {
                transform();
                bitlen += 512;
                datalen = 0;
            }
        }
    }

    // Finalize function to produce the final hash
    void final(unsigned char* hash) {
        size_t i = datalen;

        // Padding to make the data length 512 bits
        if (datalen < 56) {
            data[i++] = 0x80;
            while (i < 56)
                data[i++] = 0x00;
        }
        else {
            data[i++] = 0x80;
            while (i < 64)
                data[i++] = 0x00;
            transform();
            memset(data, 0, 56);
        }

        // Append the length of the message
        bitlen += datalen * 8;
        data[63] = bitlen;
        data[62] = bitlen >> 8;
        data[61] = bitlen >> 16;
        data[60] = bitlen >> 24;
        data[59] = bitlen >> 32;
        data[58] = bitlen >> 40;
        data[57] = bitlen >> 48;
        data[56] = bitlen >> 56;
        transform();

        // Copy the final hash state to the output hash
        for (i = 0; i < 4; ++i) {
            hash[i]      = (state[0] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 4]  = (state[1] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 8]  = (state[2] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 12] = (state[3] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 16] = (state[4] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 20] = (state[5] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 24] = (state[6] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 28] = (state[7] >> (24 - i * 8)) & 0x000000ff;
        }
    }
};

// Main function with prompt for user input
int main() {
    SHA256 sha256;            // SHA256 object for hashing
    unsigned char hash[32];    // Output hash array
    std::string inputMessage;  // Variable to store the message or file content

    // Prompt the user for input choice
    int choice;
    std::cout << "Choose one of the options below:\n";
    std::cout << "1. Enter a simple message\n";
    std::cout << "2. Enter a file path\n";
    std::cout << "3. Exit\n";
    std::cin >> choice;
    std::cin.ignore();  // Ignore any leftover newline characters

    // Handle user's choice
    if (choice == 1) {
        // Option 1: Enter a simple message
        std::cout << "Enter the message you want to hash: ";
        std::getline(std::cin, inputMessage);
    }
    else if (choice == 2) {
        // Option 2: Enter a file path
        std::string filePath;
        std::cout << "Enter the file path: ";
        std::getline(std::cin, filePath);

        // Open the file and read its contents
        std::ifstream file(filePath);
        if (!file) {
            std::cerr << "Error: Could not open the file!\n";
            return 1;
        }
        std::string line;
        while (std::getline(file, line)) {
            inputMessage += line;
        }
        file.close();
    }
    else if (choice == 3) {
        // Option 3: Exit
        std::cout << "Exiting the program.\n";
        return 0;
    }
    else {
        std::cerr << "Invalid choice! Exiting the program.\n";
        return 1;
    }

    // Convert the message to unsigned char array
    sha256.update(reinterpret_cast<const unsigned char*>(inputMessage.c_str()), inputMessage.size());

    // Finalize and get the hash
    sha256.final(hash);

    // Print the resulting hash in hexadecimal format
    std::cout << "SHA-256 Hash: ";
    for (int i = 0; i < 32; ++i) {
        printf("%02x", hash[i]);
    }
    std::cout << std::endl;

    return 0;
}
