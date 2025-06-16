#ifndef CRYPTO_H_
#define CRYPTO_H_

#include <vector>

struct EncryptionKey {
    EncryptionKey()
        : key()
        , iv()
    { }

    EncryptionKey(const std::vector<uint8_t>& inkey, const std::vector<uint8_t> & iniv)
        : key(inkey)
        , iv(iniv)
    { }

    EncryptionKey(const EncryptionKey& Copy)
        : key(Copy.key)
        , iv(Copy.iv)
    { }

    EncryptionKey(EncryptionKey&& Copy) noexcept
        : key(std::move(Copy.key))
        , iv(std::move(Copy.iv))
    { }
    
    EncryptionKey& operator = (const EncryptionKey& Other)
    {
        (*this).key = Other.key;
        (*this).iv = Other.iv;
        return *this;
    }

    EncryptionKey& operator = (EncryptionKey&& Other) noexcept
    {
        (*this).key = std::move(Other.key);
        (*this).iv = std::move(Other.iv);
        return *this;
    }

    std::vector<uint8_t> key;
    std::vector<uint8_t> iv;
};

class Crypto
{
public:
    static std::vector<uint8_t> GenerateBytes(int Bytes);

    static int GetSizeOfCheckSumSHA256();
    static std::vector<uint8_t> CreateChecksumSHA256(const uint8_t* Buffer, uint32_t Size);

    static std::vector<uint8_t> EncryptAES256(const uint8_t* data, size_t size, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv);
    static std::vector<uint8_t> DecryptAES256(const uint8_t* data, size_t size, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv);

};

#endif // CRYPTO_H_