// Self-test for functions in Sources/capldll.cpp (no DLL loading).

#include <iostream>
#include <string>
#include <vector>

#include <cstring>

#include "../Includes/cdll.h"

#include "../ExtInclude/rsa.h"
#include "../ExtInclude/osrng.h"
#include "../ExtInclude/pssr.h"
#include "../ExtInclude/sha.h"
#include "../ExtInclude/filters.h"
#include "../ExtInclude/hex.h"
#include "../ExtInclude/secblock.h"
#include "../ExtInclude/integer.h"

size_t CAPLEXPORT CAPLPASCAL RSASignMessagePSS(
  const char* privateKeyHex,
  const char* message,
  CryptoPP::byte* signature_out,
  size_t signature_out_len);

size_t CAPLEXPORT CAPLPASCAL RSASignByteArrayPSS(
  const char* privateKeyHex,
  const CryptoPP::byte* message,
  size_t messageLen,
  CryptoPP::byte* signature_out,
  size_t signature_out_len);

size_t CAPLEXPORT CAPLPASCAL ExtractPublicKeyParams(
  const char* privateKeyHex,
  CryptoPP::byte* modulusBytes,
  size_t& modulusLength,
  CryptoPP::byte* publicExponentBytes,
  size_t& publicExponentLength);

static std::string EncodePrivateKeyHex(const CryptoPP::RSA::PrivateKey& key) {
  std::string der;
  CryptoPP::StringSink derSink(der);
  key.Save(derSink);

  std::string hex;
  CryptoPP::StringSource toHex(
    der,
    true,
    new CryptoPP::HexEncoder(new CryptoPP::StringSink(hex), false));
  return hex;
}

static std::string ToHex(const CryptoPP::byte* data, size_t len) {
  std::string hex;
  CryptoPP::StringSource toHex(
    data,
    len,
    true,
    new CryptoPP::HexEncoder(new CryptoPP::StringSink(hex), false));
  return hex;
}

int main() {
  try {
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, 1024);

    const std::string privateKeyHex = EncodePrivateKeyHex(privateKey);

    const char* message = "capldll-selftest";
    std::vector<CryptoPP::byte> signature(512);

    size_t sigLen = RSASignMessagePSS(
      privateKeyHex.c_str(),
      message,
      signature.data(),
      signature.size());

    if (sigLen == 0) {
      std::cerr << "RSASignMessagePSS failed." << std::endl;
      return 1;
    }

    std::cout << "RSASignMessagePSS signature(hex): "
              << ToHex(signature.data(), sigLen) << std::endl;

    const CryptoPP::byte messageBytes[] = {0x10, 0x20, 0x30, 0x40, 0x50};
    sigLen = RSASignByteArrayPSS(
      privateKeyHex.c_str(),
      messageBytes,
      sizeof(messageBytes),
      signature.data(),
      signature.size());

    if (sigLen == 0) {
      std::cerr << "RSASignByteArrayPSS failed." << std::endl;
      return 1;
    }

    std::cout << "RSASignByteArrayPSS signature(hex): "
              << ToHex(signature.data(), sigLen) << std::endl;

    std::vector<CryptoPP::byte> modulus(512);
    std::vector<CryptoPP::byte> exponent(16);
    size_t modulusLen = modulus.size();
    size_t exponentLen = exponent.size();

    if (ExtractPublicKeyParams(
      privateKeyHex.c_str(),
      modulus.data(),
      modulusLen,
      exponent.data(),
      exponentLen) == 0) {
      std::cerr << "ExtractPublicKeyParams failed." << std::endl;
      return 1;
    }

    CryptoPP::Integer expectedModulus = privateKey.GetModulus();
    CryptoPP::Integer expectedExponent = privateKey.GetPublicExponent();

    const size_t expectedModulusLen = expectedModulus.MinEncodedSize();
    const size_t expectedExponentLen = expectedExponent.MinEncodedSize();
    std::vector<CryptoPP::byte> expectedModulusBytes(expectedModulusLen);
    std::vector<CryptoPP::byte> expectedExponentBytes(expectedExponentLen);

    expectedModulus.Encode(expectedModulusBytes.data(), expectedModulusLen);
    expectedExponent.Encode(expectedExponentBytes.data(), expectedExponentLen);

    std::cout << "ExtractPublicKeyParams modulus(hex): "
              << ToHex(modulus.data(), modulusLen) << std::endl;
    std::cout << "ExtractPublicKeyParams exponent(hex): "
              << ToHex(exponent.data(), exponentLen) << std::endl;

    std::cout << "capldll self-test complete." << std::endl;
    return 0;
  } catch (const CryptoPP::Exception& e) {
    std::cerr << "Crypto++ exception: " << e.what() << std::endl;
    return 1;
  } catch (const std::exception& e) {
    std::cerr << "Exception: " << e.what() << std::endl;
    return 1;
  }
}
