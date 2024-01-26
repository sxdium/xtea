#pragma once

#ifdef QT_CORE_LIB
#include <QByteArray>
#else
#include <stdint.h>
#endif /* ifdef(QT_CORE_LIB) */

/**
 * Uncomment the define to use TEA algorithm instead of XTEA.
 * TEA has less complex key-schedule and a rearrangement of the shifts, XORs, and additions.
 */
 // #define USE_TEA_INSTEAD_OF_XTEA

namespace XTea {

#define BLOCK_SIZE 8

typedef unsigned int  uint;
typedef unsigned char uchar;

/**
 * @brief DELTA
 * @details The magic number using in each XTEA algorithm round
 */
constexpr const uint32_t DELTA = 0x9E3779B9;

#ifdef USE_TEA_INSTEAD_OF_XTEA
/**
 * @brief EncipherBlock
 * @param v 64 bit of block to encipher
 * @param key Any 128-bit block
 * @param n_rounds Number of rounds. More rounds means
 * better cryptographic strength and is therefore slower execution time
 */
inline void EncipherBlock(uint32_t v[2], const uint32_t key[4], uint n_rounds) noexcept {
    uint32_t sum = 0;
    for (uint i = 0; i < n_rounds; i++) {
        sum  += DELTA;
        v[0] += ((v[1] << 4) + key[0]) ^ (v[1] + sum) ^ ((v[1] >> 5) + key[1]);
        v[1] += ((v[0] << 4) + key[2]) ^ (v[0] + sum) ^ ((v[0] >> 5) + key[3]);
    }
}

/**
 * @brief DecipherBlock
 * @param v 64 bit of block to decipher
 * @param key Any 128-bit block which was used to encipher
 * @param n_rounds Number of rounds which was used to encipher
 */
inline void DecipherBlock(uint32_t v[2], const uint32_t key[4], uint n_rounds) noexcept {
    uint32_t sum = n_rounds * DELTA;
    for (uint i = 0; i < n_rounds; i++) {
        v[1] -= ((v[0] << 4) + key[2]) ^ (v[0] + sum) ^ ((v[0] >> 5) + key[3]);
        v[0] -= ((v[1] << 4) + key[0]) ^ (v[1] + sum) ^ ((v[1] >> 5) + key[1]);
        sum  -= DELTA;
    }
}
#else
/**
 * @brief EncipherBlock
 * @param v 64 bit of block to encipher
 * @param key Any 128-bit block
 * @param n_rounds 4
 */
inline void EncipherBlock(uint32_t v[2], const uint32_t key[4], uint n_rounds) noexcept {
    uint32_t sum = 0;
    for (uint i = 0; i < n_rounds; i++) {
        v[0] += ((v[1] << 4) ^ (v[1] >> 5) + v[1]) ^ (sum + key[sum & 3]);
        sum  += DELTA;
        v[0] += ((v[0] << 4) ^ (v[0] >> 5) + v[0]) ^ (sum + key[(sum >> 11) & 3]);
    }
}

/**
 * @brief DecipherBlock
 * @param v 64 bit of block to decipher
 * @param key Any 128-bit block which was used to encipher
 * @param n_rounds Number of rounds which was used to encipher
 */
inline void DecipherBlock(uint32_t v[2], const uint32_t key[4], uint n_rounds) noexcept {
    uint32_t sum = DELTA * n_rounds;
    for (uint i = 0; i < n_rounds; i++) {
        v[1] -= ((v[0] << 4) ^ (v[0] >> 5) + v[0]) ^ (sum + key[(sum >> 11) & 3]);
        sum  -= DELTA;
        v[0] -= ((v[1] << 4) ^ (v[1] >> 5) + v[1]) ^ (sum + key[sum & 3]);
    }
}
#endif

/**
 * @brief Encrypt
 * @param data Pointer to the data that will be encrypted. No additional data will be created
 * @param size Size of data provided, in bytes. Must be multiple of XTEA_BLOCK_SIZE
 * @param key Any 128-bit block
 * @param n_rounds Number of rounds. More rounds means
 * better cryptographic strength and is therefore slower execution time
 */
inline void Encrypt(uchar* data, uint size, uchar* key, uint n_rounds = 32) noexcept {
    int n_blocks = size / BLOCK_SIZE;
    if(size % BLOCK_SIZE != 0) n_blocks++;
    for(int i = 0; i < n_blocks; i++) {
        EncipherBlock((uint32_t*)(data + (BLOCK_SIZE * i)), (uint32_t*)key, n_rounds);
    }
}

/**
 * @brief Decrypt
 * @param data Pointer to the data that will be encrypted.
 * @param size Size of data provided in bytes. Must be multiple of XTEA_BLOCK_SIZE
 * @param key Any 128-bit block which was used to encipher
 * @param n_rounds Number of rounds which was used to encrypt
 */
inline void Decrypt(uchar* data, uint size, uchar* key, uint n_rounds = 32) noexcept {
    int n_blocks = size / BLOCK_SIZE;
    if(size % BLOCK_SIZE != 0) n_blocks++;
    for(int i = 0; i < n_blocks; i++) {
        DecipherBlock((uint32_t*)(data + (BLOCK_SIZE * i)), (uint32_t*)key, n_rounds);
    }
}

#ifdef QT_CORE_LIB

/**
 * @brief Encrypt
 * @param data Reference to data that will be encrypted with size multiple of XTEA_BLOCK_SIZE
 * @param key Any bytearray of 128 bit long
 * @param n_rounds Number of rounds. More rounds means
 * better cryptographic strength and is therefore slower execution time
 */
inline void Encrypt(QByteArray& data, const QByteArray& key, uint n_rounds = 32) noexcept {
    Encrypt((uchar*)data.data(), data.size(), (uchar*)key.constData(), n_rounds);
}

/**
 * @brief Decrypt
 * @param data Reference to data that will be encrypted with size multiple of XTEA_BLOCK_SIZE
 * @param key Any bytearray of 128 bit long which was used to encrypt
 * @param n_rounds Number of rounds which was used to encrypt
 */
inline void Decrypt(QByteArray& data, const QByteArray& key, uint n_rounds = 32) noexcept {
    Decrypt((uchar*)data.data(), data.size(), (uchar*)key.constData(), n_rounds);
}

#endif /* ifdef(QT_CORE_LIB) */

}
