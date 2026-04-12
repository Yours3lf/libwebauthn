#pragma once

#include <string>
#include <array>

//Mostly built based on 
//https://github.com/duo-labs/py_webauthn/

//TODO just deal with CBOR directly as opposed to CBOR->JSON conversion
//TODO optimise code by removing the many many copies

//TODO change to RapidJSON once the implementation is solid
//https://github.com/nlohmann/json
#include "nlohmann/json.hpp"
using json=nlohmann::json;

//https://github.com/aklomp/base64
#include "base64/include/libbase64.h"

//https://github.com/PJK/libcbor
#include "libcbor/src/cbor.h"

//https://github.com/jimmy-park/openssl-cmake
//https://github.com/openssl/openssl
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

#include "libwebutil/WebUtil.h"

namespace libwebauthn
{

enum class COSEKey : int32_t
{
    KTY = 1,
    ALG = 3,
    // EC2, OKP
    CRV = -1,
    X = -2,
    // EC2
    Y = -3,
    // RSA
    N = -1,
    E = -2
};

enum class PubKeyType : int32_t
{
    OKP = 1,
    EC2 = 2,
    RSA = 3
};

enum class PubKeyAlg : int32_t
{
    ECDSA_SHA_256 = -7,
    EDDSA = -8,
    ECDSA_SHA_512 = -36,
    RSASSA_PSS_SHA_256 = -37,
    RSASSA_PSS_SHA_384 = -38,
    RSASSA_PSS_SHA_512 = -39,
    RSASSA_PKCS1_v1_5_SHA_256 = -257,
    RSASSA_PKCS1_v1_5_SHA_384 = -258,
    RSASSA_PKCS1_v1_5_SHA_512 = -259,
    RSASSA_PKCS1_v1_5_SHA_1 = -65535
};

enum class PubKeyCrv : int32_t
{
    P256 = 1,       //EC2, NIST P-256 also known as secp256r1
    P384 = 2,       //EC2, NIST P-384 also known as secp384r1
    P521 = 3,       //EC2, NIST P-521 also known as secp521r1
    ED25519 = 6     //OKP, Ed25519 for use w/ EdDSA only
};

const std::vector<PubKeyAlg> defaultSupportedPubKeyAlgos = {
    PubKeyAlg::ECDSA_SHA_256, 
    PubKeyAlg::RSASSA_PKCS1_v1_5_SHA_256
};

struct DecodedPublicKey
{
    PubKeyType kty;
    PubKeyAlg alg; 
};

int PublicKeyCrvToOpenSSLNid(PubKeyCrv crv)
{
    switch(crv)
    {
        case PubKeyCrv::P256: return NID_X9_62_prime256v1;
        case PubKeyCrv::P384: return NID_secp384r1;
        case PubKeyCrv::P521: return NID_secp521r1;
        //case ED25519: return 0; //this EDDSA, not ECDSA so this is different
        default: assert(0);
    }
}

struct DecodedPublicKeyOKP : public DecodedPublicKey
{
    struct {
        EVP_PKEY* pkey = nullptr;
    } crypto;

    void build(
        PubKeyCrv crv,
        const std::vector<uint8_t>& x
    )
    {
        EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
            (int)crv, //EVP_PKEY_ED25519,
            NULL,
            x.data(),
            x.size()
        );

        crypto.pkey = pkey;
    }

    void destroy()
    {
        EVP_PKEY_free(crypto.pkey);
    }
};

struct DecodedPublicKeyEC2 : public DecodedPublicKey
{
    struct {
    EC_KEY* ec_key = nullptr;
    BIGNUM* bn_x = nullptr;
    BIGNUM* bn_y = nullptr;
    EC_POINT* point = nullptr;
    EVP_PKEY* pkey = nullptr;
    } crypto;

    void build(
        PubKeyCrv crv,
        const std::vector<uint8_t>& x,
        const std::vector<uint8_t>& y
    )
    {
        EC_KEY* ec_key = EC_KEY_new_by_curve_name(PublicKeyCrvToOpenSSLNid(crv));

        BIGNUM* bn_x = BN_bin2bn(x.data(), x.size(), nullptr);
        BIGNUM* bn_y = BN_bin2bn(y.data(), y.size(), nullptr);

        EC_POINT* point = EC_POINT_new(EC_KEY_get0_group(ec_key));
        EC_POINT_set_affine_coordinates_GFp(
            EC_KEY_get0_group(ec_key),
            point,
            bn_x,
            bn_y,
            nullptr
        );

        EC_KEY_set_public_key(ec_key, point);

        EVP_PKEY* pkey = EVP_PKEY_new();
        EVP_PKEY_assign_EC_KEY(pkey, ec_key);

        crypto.ec_key = ec_key;
        crypto.bn_x = bn_x;
        crypto.bn_y = bn_y;
        crypto.point = point;
        crypto.pkey = pkey;
    }

    void destroy()
    {
        EVP_PKEY_free(crypto.pkey);
        EC_POINT_free(crypto.point);
        BN_free(crypto.bn_x);
        BN_free(crypto.bn_y);
    }
};

struct DecodedPublicKeyRSA : public DecodedPublicKey
{
    struct {
        BIGNUM* n_bn = nullptr;
        BIGNUM* e_bn = nullptr;
        RSA* rsa = nullptr;
        EVP_PKEY* pkey = nullptr;
    } crypto;

    void build(
        std::vector<uint8_t> n,
        std::vector<uint8_t> e
    )
    {
        BIGNUM* n_bn = BN_bin2bn(n.data(), n.size(), nullptr);
        BIGNUM* e_bn = BN_bin2bn(e.data(), e.size(), nullptr);

        RSA* rsa = RSA_new();
        RSA_set0_key(rsa, n_bn, e_bn, nullptr);

        EVP_PKEY* pkey = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(pkey, rsa);

        crypto.n_bn = n_bn;
        crypto.e_bn = e_bn;
        crypto.rsa = rsa;
        crypto.pkey = pkey;
    }

    void destroy()
    {
        EVP_PKEY_free(crypto.pkey);
        RSA_free(crypto.rsa);
        BN_free(crypto.n_bn);
        BN_free(crypto.e_bn);
    }
};

void destroyPubKey(DecodedPublicKey* pubKey)
{
    assert(pubKey);

    switch(pubKey->kty)
    {
        case PubKeyType::OKP: 
        {
            reinterpret_cast<DecodedPublicKeyOKP*>(pubKey)->destroy();
            break;
        }
        case PubKeyType::EC2:
        {
            reinterpret_cast<DecodedPublicKeyEC2*>(pubKey)->destroy();
            break;
        }
        case PubKeyType::RSA:
        {
            reinterpret_cast<DecodedPublicKeyRSA*>(pubKey)->destroy();
            break;
        }
    }

    delete pubKey;
}

/**
    Attributes:
    `up`: [U]ser was [P]resent
    `uv`: [U]ser was [V]erified
    `be`: [B]ackup [E]ligible
    `bs`: [B]ackup [S]tate
    `at`: [AT]tested credential is included
    `ed`: [E]xtension [D]ata is included
/**/
class AuthenticatorDataFlags
{
private: 
    uint8_t byte;
public:
    AuthenticatorDataFlags(){}
    AuthenticatorDataFlags(uint8_t b) : byte(b) {};

    bool up() { return byte & (1 << 0); }
    bool uv() { return byte & (1 << 2); }
    bool be() { return byte & (1 << 3); }
    bool bs() { return byte & (1 << 4); }
    bool at() { return byte & (1 << 6); }
    bool ed() { return byte & (1 << 7); }
};

/**
    Attributes:
    `aaguid`: A 128-bit identifier indicating the type and vendor of the authenticator
    `credential_id`: The ID of the private/public key pair generated by the authenticator
    `credential_public_key`: The public key generated by the authenticator

/**/
struct AttestedCredentialData
{
    std::array<uint8_t, 16> aaguid;
    std::vector<uint8_t> credentialId;
    std::vector<uint8_t> credentialPublicKey; //in CBOR
};

/**
    Attributes:
    `rp_id_hash`: A SHA-256 hash of the website origin on which the registration or authentication ceremony took place
    `flags`: Properties about the user and registration, where applicable
    `sign_count`: The number of times the credential was used
    (optional) `attested_credential_data`: Information about the credential created during a registration ceremony
    (optional) `extensions`: CBOR-encoded extension data corresponding to extensions specified in the registration or authentication ceremony options
/**/
struct AuthenticatorData
{
    std::array<uint8_t, 32> rpIdHash;
    AuthenticatorDataFlags flags;
    uint32_t signCount = 0;
    AttestedCredentialData attestedCredData;
    std::vector<uint8_t> extensions; //in CBOR
};

/**
    Attributes:
    `fmt`: The attestation statement's format
    `att_stmt`: An attestation statement to be verified according to the format
    `auth_data`: Contextual information provided by authenticator
/**/
struct AttestationObject
{
    std::string fmt;
    AuthenticatorData authenticatorData;
    json attStmt;
};

/**
    Attributes:
    `credential_id`: The generated credential's ID
    `credential_public_key`: The generated credential's public key
    `sign_count`: How many times the authenticator says the credential was used
    `aaguid`: A 128-bit identifier indicating the type and vendor of the authenticator
    `fmt`: The attestation format
    `credential_type`: The literal string "public-key"
    `user_verified`: Whether the user was verified by the authenticator
    `attestation_object`: The raw attestation object for later scrutiny
/**/
struct VerifiedRegistration
{
    std::vector<uint8_t> credentialId;
    std::vector<uint8_t> credentialPublicKey;
    uint32_t signCount = 0;
    std::string aaguid;
    std::string fmt;
    std::string credType;
    bool userVerified;
    std::string attestationObjectBase64Str;
    bool isMultiDevice;
    bool isBackedUp;
};

struct VerifiedAuthentication
{
    std::vector<uint8_t> credentialId;
    uint32_t newSignCount;
    bool isMultiDevice;
    bool isBackedUp;
    bool userVerified;
};

struct AuthenticatorSelectionCriteria
{
    std::string attachment; //platform, cross-platform
    std::string residentKey; //discouraged, preferred, required
    bool requireResidentKey = false;
    std::string userVerification = "preferred"; //discouraged, preferred, required
};

/**
    Attributes:
    `type`: The literal string `"public-key"`
    `id`: The sequence of bytes representing the credential's ID
    (optional) `transports`: The types of connections to the client/browser the authenticator supports
/**/
struct PublicKeyCredentialDescriptor
{
    std::vector<uint8_t> id;
    std::string type = "public-key";
    std::vector<std::string> transports;
};

std::string aaguidToString(const std::array<uint8_t, 16>& aaguid)
{
    std::string res = bytesToString(aaguid);
    std::string resDash;
    resDash.resize(36);
    int offsetS = 0;
    int offsetD = 0;
    std::copy(res.begin() + offsetS, res.begin() + offsetS + 8, resDash.begin() + offsetD);
    offsetS += 8;
    offsetD += 8 + 1;
    resDash[offsetS] = '-';
    std::copy(res.begin() + offsetS, res.begin() + offsetS + 4, resDash.begin() + offsetD);
    offsetS += 4;
    offsetD += 4 + 1;
    resDash[offsetS] = '-';
    std::copy(res.begin() + offsetS, res.begin() + offsetS + 4, resDash.begin() + offsetD);
    offsetS += 4;
    offsetD += 4 + 1;
    resDash[offsetS] = '-';
    std::copy(res.begin() + offsetS, res.begin() + offsetS + 4, resDash.begin() + offsetD);
    offsetS += 4;
    offsetD += 4 + 1;
    resDash[offsetS] = '-';
    std::copy(res.begin() + offsetS, res.begin() + offsetS + 12, resDash.begin() + offsetD);

    return resDash;
}

std::vector<uint8_t> generateRandomBytes(int length)
{
    static bool inited = false;
    if(!inited)
    {
        //init random number generator
        srand( time(nullptr) );
        inited = true;
    }

    int mod = length % 4;
    std::vector<uint8_t> raw(length - mod + (mod ? 4 : 0));
    int count = raw.size() / 4;
    for(int c = 0; c < count; ++c)
    {
        int r = rand();
        *(uint32_t*)(raw.data() + c * 4) = *(uint32_t*)&r;
    }
    return std::vector<uint8_t>(raw.begin(), raw.begin() + length);
}

std::array<uint8_t, SHA256_DIGEST_LENGTH> sha256(const std::string& str)
{
    std::array<uint8_t, SHA256_DIGEST_LENGTH> hash;
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash.data(), &sha256);
    return hash;
}

std::string encodeBase64Url(const char* data, size_t len)
{
    std::string str;
    {
        str.resize(len * 2);
        size_t size = str.size();
        base64_encode(data, len, str.data(), &size, 0);
        str.resize(size);
        str = urlSafeBase64(str);
    }

    return str;
}

std::string encodeBase64Url(const std::string& str)
{
    return encodeBase64Url(str.data(), str.size());
}

std::string decodeBase64Url(const char* data, uint32_t len)
{
    std::string normalisedStr;
    normalisedStr.resize(len);
    std::copy(data, data + len, normalisedStr.data());
    normalisedStr = normalizeBase64(normalisedStr);
    
    std::string str;
    {
        str.resize(len);
        size_t size = str.size();
        int res = base64_decode(normalisedStr.data(), normalisedStr.size(), str.data(), &size, 0);
        assert(res == 1);
        str.resize(size);
    }

    return str;
}

std::string decodeBase64Url(const std::string& str)
{
    return decodeBase64Url(str.data(), str.size());
}

size_t getCBORByteSize(const char* data, size_t len)
{
    struct cbor_load_result result;
    cbor_item_t* cbor = cbor_load((cbor_data)data, len, &result);
    assert(result.error.code == CBOR_ERR_NONE);
    assert(cbor);

    size_t res = cbor_serialized_size(cbor);

    cbor_decref(&cbor);

    return res;
}

size_t getCBORByteSize(const std::string& CBORStr)
{
    return getCBORByteSize(CBORStr.data(), CBORStr.size());
}

int64_t cborGetInt64(cbor_item_t* i)
{
    return -(int64_t)cbor_get_int(i) - 1;
}

json traverseCBOR(cbor_item_t* decoded)
{
    json j;
    
    if(cbor_isa_map(decoded))
    {
        cbor_pair* handle = cbor_map_handle(decoded);
        size_t mapSize = cbor_map_size(decoded);

        for (size_t i = 0; i < mapSize; i++)
        {
            cbor_item_t* key = handle[i].key;
            cbor_item_t* value = handle[i].value;

            if (
                !(cbor_isa_string(key) ||
                  cbor_isa_uint(key)   ||
                  cbor_isa_negint(key))
            )
            {
                continue;
            }

            std::string keyStr;

            if(cbor_isa_string(key))
            {
                keyStr = std::string((char *)cbor_string_handle(key), cbor_string_length(key));
            }
            else if(cbor_isa_uint(key))
            {
                keyStr = std::to_string(cbor_get_int(key));
            }
            else if(cbor_isa_negint(key))
            {
                keyStr = std::to_string(cborGetInt64(key));
            }

            if(cbor_isa_string(value))
            {
                std::string valStr((char *)cbor_string_handle(value), cbor_string_length(value));
                j[keyStr] = valStr;
            }
            else if(cbor_isa_bytestring(value))
            {
                size_t len = cbor_bytestring_length(value);
                uint8_t* data = cbor_bytestring_handle(value);
                std::vector<uint8_t> dataVec(data, data + len);
                j[keyStr] = dataVec;
            }
            else if(cbor_isa_uint(value))
            {
                j[keyStr] = cbor_get_int(value);
            }
            else if(cbor_isa_negint(value))
            {
                j[keyStr] = cborGetInt64(value);
            }
            else if(cbor_isa_array(value) || cbor_isa_map(value))
            {
                j[keyStr] = traverseCBOR(value);
            }
        }
    }
    else if(cbor_isa_array(decoded))
    {
        size_t arraySize = cbor_array_size(decoded);
        
        for(size_t i = 0; i < arraySize; ++i)
        {
            cbor_item_t* value = cbor_array_get(decoded, i);
            
            if(cbor_isa_string(value))
            {
                std::string valStr((char *)cbor_string_handle(value), cbor_string_length(value));
                j.push_back(valStr);
            }
            else if(cbor_isa_bytestring(value))
            {
                size_t len = cbor_bytestring_length(value);
                uint8_t* data = cbor_bytestring_handle(value);
                std::vector<uint8_t> dataVec(data, data + len);
                j.push_back(dataVec);
            }
            else if(cbor_isa_uint(value))
            {
                j.push_back(cbor_get_int(value));
            }
            else if(cbor_isa_negint(value))
            {
                j.push_back(cborGetInt64(value));
            }
            else if(cbor_isa_array(value) || cbor_isa_map(value))
            {
                j.push_back(traverseCBOR(value));
            }
        }
    }

    return j;
}

json convertCBORtoJSON(const char* data, size_t len)
{
    struct cbor_load_result result;
    cbor_item_t* cbor = cbor_load((cbor_data)data, len, &result);
    assert(result.error.code == CBOR_ERR_NONE);
    assert(cbor);

    cbor_describe(cbor, stdout);

    json j = traverseCBOR(cbor);

    cbor_decref(&cbor);

    return j;
}

json convertCBORtoJSON(const std::string& CBORStr)
{
    return convertCBORtoJSON(CBORStr.data(), CBORStr.size());
}

bool verifySignature(
    const DecodedPublicKey* decodedCredentialPublicKey,
    const std::string& signature,
    const std::string& signedData
)
{
    assert(decodedCredentialPublicKey);

    PubKeyAlg alg = decodedCredentialPublicKey->alg;
    if(alg == PubKeyAlg::ECDSA_SHA_256)
    {
        DecodedPublicKeyEC2* pubkey = (DecodedPublicKeyEC2*)decodedCredentialPublicKey;

        //verify signature
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();

        EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pubkey->crypto.pkey);

        int ret = EVP_DigestVerify(
            ctx,
            (const unsigned char*)signature.data(),
            signature.size(),
            (const unsigned char*)signedData.data(),
            signedData.size()
        );

        EVP_MD_CTX_free(ctx);

        if (ret == 1) 
        {
            // Signature valid
            return true;
        } 
        else if (ret == 0) 
        {
            // Signature invalid
            return false;
        } 
        else 
        {
            // Error
            std::cerr << "error verifying signature" << std::endl;
            ERR_print_errors_fp(stderr);
            return false;
        }
    }
    else if(alg == PubKeyAlg::RSASSA_PKCS1_v1_5_SHA_256)
    {
        DecodedPublicKeyRSA* pubkey = (DecodedPublicKeyRSA*)decodedCredentialPublicKey;

        //verify signature
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();

        EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pubkey->crypto.pkey);

        // Important: explicitly set padding for RSA
        EVP_PKEY_CTX* pctx = EVP_MD_CTX_pkey_ctx(ctx);
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING);

        int rc = EVP_DigestVerify(
            ctx,
            (const unsigned char*)signature.data(),
            signature.size(),
            (const unsigned char*)signedData.data(),
            signedData.size()
        );

        EVP_MD_CTX_free(ctx);

        if (rc == 1) 
        {
            return true;
        } 
        else if (rc == 0) 
        {
            return false;
        } 
        else 
        {
            // Error
            std::cerr << "error verifying signature" << std::endl;
            ERR_print_errors_fp(stderr);
            return false;
        }
    }
    else
    {
        std::cerr << "unsupported public key algo " << (int32_t)alg << std::endl;
        return false;
    }
}

AuthenticatorData parseAuthenticatorData(const std::vector<uint8_t>& authData)
{
    AuthenticatorData ad;

    if(authData.size() < 37)
    { 
        std::cerr << "auth data too small: " << authData.size() << std::endl;
        return ad;
    }

    uint32_t offset = 0;

    std::array<uint8_t, 32> rpIdHash;
    std::copy(authData.begin() + offset, authData.begin() + offset + 32, rpIdHash.begin());
    offset += 32;

    uint8_t flagBytes = authData[offset];
    offset += 1;

    uint32_t signCount = *(uint32_t*)(authData.data() + offset);
    signCount = swapEndianness(signCount);
    offset += 4;

    AuthenticatorDataFlags flags(flagBytes);

    ad.rpIdHash = rpIdHash;
    ad.flags = flags;
    ad.signCount = signCount;

    if(flags.at())
    {
        std::array<uint8_t, 16> aaguid;
        std::copy(authData.begin() + offset, authData.begin() + offset + 16, aaguid.begin());
        offset += 16;

        uint16_t credentialIdLen = *(uint16_t*)(authData.data() + offset);
        credentialIdLen = swapEndianness(credentialIdLen);
        offset += 2;

        std::vector<uint8_t> credentialId(authData.begin() + offset, authData.begin() + offset + credentialIdLen);
        offset += credentialIdLen;

        /**
        Some authenticators incorrectly compose authData when using EdDSA for their public keys.
        A CBOR "Map of 3 items" (0xA3) should be "Map of 4 items" (0xA4), and if we manually adjust
        the single byte there's a good chance the authData can be correctly parsed. Let's try to
        detect when this happens and gracefully handle it.
        /**/
        std::array<uint8_t, 17> badEddsaCbor = {
            0xa3, 0x01, 0x63, 0x4f, 0x4b, 0x50, 0x03, 0x27, 0x20, 0x67, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39
        };

        std::array<uint8_t, 17> candidateArray;
        std::copy(authData.begin() + offset, authData.begin() + offset + badEddsaCbor.size(), candidateArray.begin());

        if(badEddsaCbor == candidateArray)
        {
            //the dark side of coding is a pathway to many abilites some consider to be... unnatural
            *(uint8_t*)(authData.data() + offset) = 0xa4;
        }

        size_t publicKeyCborSize = getCBORByteSize(std::string(authData.begin() + offset, authData.end()));
        
        ad.attestedCredData = {
            aaguid, credentialId, std::vector<uint8_t>(authData.begin() + offset, authData.begin() + offset + publicKeyCborSize)
        };

        offset += publicKeyCborSize;
    }

    if(flags.ed())
    {
        size_t extensionCborSize = getCBORByteSize(std::string(authData.begin() + offset, authData.end()));

        ad.extensions = std::vector<uint8_t>(authData.begin() + offset, authData.begin() + offset + extensionCborSize);
        offset += extensionCborSize;
    }

    if(offset < authData.size())
    {
        std::cerr << "leftover bytes detected while parsing authenticator data" << std::endl;
    }

    return ad;
}

bool decodeCredentialPublicKey(
    const std::vector<uint8_t>& key, //in cbor
    DecodedPublicKey** decodedKey //caller needs to destroy/free this
)
{
    assert(decodedKey);

    if(key[0] == 0x04)
    {
        //special case for older Fido devices
        DecodedPublicKeyEC2* keyPtr = new DecodedPublicKeyEC2();
        keyPtr->kty = PubKeyType::EC2;
        keyPtr->alg = PubKeyAlg::ECDSA_SHA_256;
        keyPtr->build(
            PubKeyCrv::P256,
            std::vector<uint8_t>(key.begin()+1, key.begin()+33),
            std::vector<uint8_t>(key.begin()+33, key.begin()+65)
        );
        *decodedKey = keyPtr;
        return true;
    }

    json keyJSON = convertCBORtoJSON((const char*)key.data(), key.size());
    std::cout << keyJSON.dump(2) << std:: endl;

    PubKeyType kty = (PubKeyType)keyJSON[std::to_string((int32_t)COSEKey::KTY)];
    PubKeyAlg alg = (PubKeyAlg)keyJSON[std::to_string((int32_t)COSEKey::ALG)];

    if(kty == PubKeyType::OKP)
    {
        int32_t crv = keyJSON[std::to_string((int32_t)COSEKey::CRV)];
        std::vector<uint8_t> x = keyJSON[std::to_string((int32_t)COSEKey::X)];
        DecodedPublicKeyOKP* keyPtr = new DecodedPublicKeyOKP();
        keyPtr->kty = kty;
        keyPtr->alg = alg;
        keyPtr->build((PubKeyCrv)crv, x);
        *decodedKey = keyPtr;
    }
    else if(kty == PubKeyType::EC2)
    {
        int32_t crv = keyJSON[std::to_string((int32_t)COSEKey::CRV)];
        std::vector<uint8_t> x = keyJSON[std::to_string((int32_t)COSEKey::X)];
        std::vector<uint8_t> y = keyJSON[std::to_string((int32_t)COSEKey::Y)];
        DecodedPublicKeyEC2* keyPtr = new DecodedPublicKeyEC2();
        keyPtr->kty = kty;
        keyPtr->alg = alg;
        keyPtr->build((PubKeyCrv)crv, x, y);
        *decodedKey = keyPtr;
    }
    else if(kty == PubKeyType::RSA)
    {
        std::vector<uint8_t> n = keyJSON[std::to_string((int32_t)COSEKey::N)];
        std::vector<uint8_t> e = keyJSON[std::to_string((int32_t)COSEKey::E)];
        DecodedPublicKeyRSA* keyPtr = new DecodedPublicKeyRSA();
        keyPtr->kty = kty;
        keyPtr->alg = alg;
        keyPtr->build(n, e);
        *decodedKey = keyPtr;
    }

    return true;
}

bool generateSignupChallenge(
    json& j, //output 
    const std::string& rpId,
    const std::string& rpName,
    const std::string& userName,
    const std::string& userId = "",
    const std::string& userDisplayName = "",
    const std::string& challenge = "",
    int timeout = 60000,
    const std::string& attestation = "none", //none, indirect, direct, enterprise
    const AuthenticatorSelectionCriteria* selectionCriteria = nullptr,
    const std::vector<PublicKeyCredentialDescriptor>& excludeCredentials = {},
    const std::vector<PubKeyAlg>& supportedPubKeyAlgos = defaultSupportedPubKeyAlgos,
    const std::vector<std::string>& hints = {}
)
{
    if(rpId.empty())
    {
        std::cerr << "rpId cannot be empty" << std::endl;
        return false;
    }

    if(rpName.empty())
    {
        std::cerr << "rpName cannot be empty" << std::endl;
        return false;
    }

    if(userName.empty())
    {
        std::cerr << "userName cannot be empty" << std::endl;
        return false;
    }

    std::string userIdStr;
    if(userId.empty())
    {
        std::vector<uint8_t> bytes = generateRandomBytes(64);
        userIdStr = encodeBase64Url((const char*)&bytes[0], bytes.size());
    }
    else
    {
        userIdStr = userId;
    }

    std::string userDisplayNameStr = userDisplayName.empty() ? userName : userDisplayName;

    std::string challengeStr;
    if(challenge.empty())
    {
        std::vector<uint8_t> bytes = generateRandomBytes(64);
        challengeStr = encodeBase64Url((const char*)&bytes[0], bytes.size());
    }
    else
    {
        challengeStr = challenge;
    }

    json response;

    response["createCredentialArgs"] = {};

    response["createCredentialArgs"]["publicKey"]["rp"] = {
        {"id", rpId},
        {"name", rpName}
    };

    response["createCredentialArgs"]["publicKey"]["user"] = {
        {"id", userIdStr},
        {"name", userName},
        {"displayName", userDisplayNameStr}
    };

    response["createCredentialArgs"]["publicKey"]["challenge"] = challengeStr;

    for(size_t c = 0; c < supportedPubKeyAlgos.size(); ++c)
    {
        response["createCredentialArgs"]["publicKey"]["pubKeyCredParams"][c]["alg"] = supportedPubKeyAlgos[c]; 
        response["createCredentialArgs"]["publicKey"]["pubKeyCredParams"][c]["type"] = "public-key";
    }

    response["createCredentialArgs"]["publicKey"]["timeout"] = timeout;
    response["createCredentialArgs"]["publicKey"]["attestation"] = attestation;

    for(size_t c = 0; c < excludeCredentials.size(); ++c)
    {
        response["createCredentialArgs"]["publicKey"]["excludeCredentials"][c]["id"] = excludeCredentials[c].id;
        response["createCredentialArgs"]["publicKey"]["excludeCredentials"][c]["type"] = excludeCredentials[c].type;
        for(size_t d = 0; d < excludeCredentials[c].transports.size(); ++d)
        {
            response["createCredentialArgs"]["publicKey"]["excludeCredentials"][c]["transports"][d] = excludeCredentials[c].transports[d];
        }
    }

    response["createCredentialArgs"]["publicKey"]["hints"] = hints;

    if(selectionCriteria)
    {   
        response["createCredentialArgs"]["publicKey"]["authenticatorSelection"]["authenticatorAttachment"] = selectionCriteria->attachment;
        response["createCredentialArgs"]["publicKey"]["authenticatorSelection"]["residentKey"] = selectionCriteria->residentKey;
        response["createCredentialArgs"]["publicKey"]["authenticatorSelection"]["requireResidentKey"] = 
            selectionCriteria->residentKey == "required" ? true : selectionCriteria->requireResidentKey;
        response["createCredentialArgs"]["publicKey"]["authenticatorSelection"]["userVerification"] = selectionCriteria->userVerification;
    }

    j = response;

    return true;
}

bool verifySignupResponse(
        const json& j, //input credential object
        VerifiedRegistration& v, //output object
        const std::string& expectedChallenge,
        const std::string& expectedRpId,
        const std::string& expectedOrigin,
        bool requireUserPresence = true,
        bool requireUserVerification = false,
        const std::vector<PubKeyAlg>& supportedPubKeyAlgos = defaultSupportedPubKeyAlgos
    )
{
    std::string rawIdBase64Str = j["rawId"];
    std::string credID = j["id"];

    if(credID != rawIdBase64Str)
    {
        std::cerr << "raw cred id: " << rawIdBase64Str << " and credID don't match " << credID << std::endl;
        return false;
    }

    std::string type = j["type"];

    if (type != "public-key")
    {
        std::cerr << "type: " << type << " isn't set properly" << std::endl;
        return false;
    }
    
    std::string clientDataJSONBase64Str = j["response"]["clientDataJSON"];
    json clientData = json::parse(decodeBase64Url(clientDataJSONBase64Str));
    std::cout << clientData.dump(2) << std::endl;

    if(clientData["type"] != "webauthn.create")
    {
        std::cerr << "clientdata type: " << clientData["type"] << " isn't set properly" << std::endl;
        return false;
    } 

    if(clientData["challenge"] != expectedChallenge)
    {
        std::cerr << "challenges don't match" << std::endl;
        std::cerr << "received: " << clientData["challenge"] << " != expected: " << expectedChallenge << std::endl;
        return false;
    }

    if(clientData["origin"] != expectedOrigin)
    {
        std::cerr << "origin: " << clientData["origin"] << " != expected: " << expectedOrigin << std::endl;
        return false;
    }

    std::string attestationObjectBase64Str = j["response"]["attestationObject"];
    std::string attestationObjectStr = decodeBase64Url(attestationObjectBase64Str);
    json attestationObjectJSON = convertCBORtoJSON(attestationObjectStr);
    std::cout << attestationObjectJSON.dump(2) << std::endl;

    AttestationObject attestationObject;
    attestationObject.authenticatorData = parseAuthenticatorData(attestationObjectJSON["authData"]);
    attestationObject.fmt = attestationObjectJSON["fmt"];
    attestationObject.attStmt = attestationObjectJSON["attStmt"];

    auto expectedRpIdSHA256 = sha256(expectedRpId);

    if(expectedRpIdSHA256 != attestationObject.authenticatorData.rpIdHash)
    {
        std::cerr << "auth data rpIdHash: ";
        for(auto b : attestationObject.authenticatorData.rpIdHash)
        {
            std::cerr << b;
        }
        std::cerr << " doesn't match expected rpId Sha256: ";
        for(auto b : expectedRpIdSHA256)
        {
            std::cerr << b;
        }
        std::cerr << std::endl;
        return false;
    }

    if(requireUserPresence && !attestationObject.authenticatorData.flags.up())
    {
        std::cerr << "user presence was required, but wasn't present during auth" << std::endl;
        return false;
    }

    if(requireUserVerification && !attestationObject.authenticatorData.flags.uv())
    {
        std::cerr << "user verification was required, but wasn't verified during auth" << std::endl;
        return false;
    }

    if(attestationObject.authenticatorData.attestedCredData.credentialId.empty())
    {
        std::cerr << "authenticator didn't provide a credential id" << std::endl;
        return false;
    }

    if(attestationObject.authenticatorData.attestedCredData.credentialPublicKey.empty())
    {
        std::cerr << "authenticator didn't provide a credential pub key" << std::endl;
        return false;
    }
    
    if(attestationObject.authenticatorData.attestedCredData.credentialPublicKey[0] == 0x04)
    {
        //TODO special case for older Fido devices
        //https://github.com/duo-labs/py_webauthn/blob/master/webauthn/helpers/decode_credential_public_key.py#L36
    }
    
    DecodedPublicKey* credentialPublicKey = nullptr;
    if(!decodeCredentialPublicKey(attestationObject.authenticatorData.attestedCredData.credentialPublicKey, &credentialPublicKey))
    {
        std::cerr << "failed to decode credential public key" << std::endl;
        return false;
    }

    if(std::find(supportedPubKeyAlgos.begin(), supportedPubKeyAlgos.end(), credentialPublicKey->alg) == supportedPubKeyAlgos.end())
    {
        std::cerr << "pub key alg: " << (int32_t)credentialPublicKey->alg << " not supported" << std::endl;
        return false;
    }

    //so far so good but let's verify the attestation object
    bool verified = false;

    if(attestationObject.fmt == "none")
    {
        if(!attestationObject.attStmt.empty())
        {
            std::cerr << "attestation object with fmt none should not have a statement " << attestationObject.attStmt.dump(2) << std::endl;
            return false;
        }

        verified = true;
    }
    //TODO...
    //https://github.com/duo-labs/py_webauthn/blob/master/webauthn/registration/verify_registration_response.py#L207
    else if(attestationObject.fmt == "fido-u2f")
    {
        //security keys that implement the FIDO U2F standard use this format
        //verified = verifyFidoU2f(........);
    }
    else if(attestationObject.fmt == "packed")
    {
        //a generic attestation format that is commonly used by devices whose 
        //sole function is as a WebAuthn authenticator, such as security keys
        //verified = verifyPacked(........);
    }
    else if(attestationObject.fmt == "tpm")
    {
        //the Trusted Platform Module (TPM) is a set of specifications from 
        //the Trusted Platform Group (TPG). This attestation format is commonly 
        //found in desktop computers and is used by Windows Hello as its preferred 
        //attestation format
        //verified = verifyTpm(........);
    }
    else if(attestationObject.fmt == "apple")
    {
        //exclusively used by Apple for certain types of Apple devices
        //verified = verifyApple(........);
    }
    else if(attestationObject.fmt == "android-safetynet")
    {
        //prior to Android Key Attestation, the only option for Android devices 
        //was to create Android SafetyNet attestations
        //verified = verifyAndroidSafetyNet(........);
    }
    else if(attestationObject.fmt == "android-key")
    {
        //one of the features added in Android O was Android Key Attestation, 
        //which enables the Android operating system to attest to keys
        //verified = verifyAndroidKey(........);
    }
    else
    {
        std::cerr << "unsupported attestation format: " << attestationObject.fmt << std::endl;
        return false;
    }

    if(!verified)
    {
        std::cerr << "attestation statement couldn't be verified" << std::endl;
        return false;
    }

    bool isMultiDevice = attestationObject.authenticatorData.flags.be();
    bool isBackedUp = attestationObject.authenticatorData.flags.bs();

    if(!isMultiDevice && isBackedUp)
    {
        std::cerr << "Single device credential indicated that it was backed up, which should be impossible" << std::endl;
        return false;
    }

    v = VerifiedRegistration {
        attestationObject.authenticatorData.attestedCredData.credentialId,
        attestationObject.authenticatorData.attestedCredData.credentialPublicKey,
        attestationObject.authenticatorData.signCount,
        aaguidToString(attestationObject.authenticatorData.attestedCredData.aaguid),
        attestationObject.fmt,
        type,
        attestationObject.authenticatorData.flags.uv(),
        attestationObjectBase64Str,
        isMultiDevice,
        isBackedUp
    };

    destroyPubKey(credentialPublicKey);

    return true;
}

bool generateLoginChallenge(
    json& j, //output
    const std::string& rpId,
    const std::string& challenge = "",
    uint32_t timeout = 60000,
    const std::vector<PublicKeyCredentialDescriptor>& allowCredentials = {},
    std::string userVerification = "preferred" //preferred, required, discouraged
)
{
    if(rpId.empty())
    {
        std::cerr << "rpId cannot be empty" << std::endl;
        return false;
    }

    std::string challengeStr;
    if(challenge.empty())
    {
        std::vector<uint8_t> bytes = generateRandomBytes(64);
        challengeStr = encodeBase64Url((const char*)&bytes[0], bytes.size());
    }
    else
    {
        challengeStr = challenge;
    }

    json response;

    response["getCredentialArgs"] = {};
    
    response["getCredentialArgs"]["publicKey"]["rpId"] = rpId;
    response["getCredentialArgs"]["publicKey"]["challenge"] = challengeStr;
    response["getCredentialArgs"]["publicKey"]["timeout"] = timeout;
    response["getCredentialArgs"]["publicKey"]["userVerification"] = userVerification;
    
    for(size_t c = 0; c < allowCredentials.size(); ++c)
    {
        response["createCredentialArgs"]["publicKey"]["allowCredentials"][c]["id"] = allowCredentials[c].id;
        response["createCredentialArgs"]["publicKey"]["allowCredentials"][c]["type"] = allowCredentials[c].type;
        for(size_t d = 0; d < allowCredentials[c].transports.size(); ++d)
        {
            response["createCredentialArgs"]["publicKey"]["allowCredentials"][c]["transports"][d] = allowCredentials[c].transports[d];
        }
    }

    j = response;

    return true;
}

bool verifyLoginResponse(
    const json& j, //input
    VerifiedAuthentication& v, //output
    const std::string& expectedChallenge,
    const std::string& expectedRpId,
    const std::string& expectedOrigin,
    const std::vector<uint8_t>& credentialPublicKey,
    uint32_t credentialCurrentSignCount,
    bool requireUserVerification = false
)
{
    std::string rawIdBase64Str = j["rawId"];
    std::string credID = j["id"];

    if(credID != rawIdBase64Str)
    {
        std::cerr << "raw cred id: " << rawIdBase64Str << " and credID don't match " << credID << std::endl;
        return false;
    }

    std::string type = j["type"];

    if (type != "public-key")
    {
        std::cerr << "type: " << type << " isn't set properly" << std::endl;
        return false;
    }

    std::string clientDataJSONBase64Str = j["response"]["clientDataJSON"];
    std::string clientDataJSONStr = decodeBase64Url(clientDataJSONBase64Str);
    json clientData = json::parse(clientDataJSONStr);
    std::cout << clientData.dump(2) << std::endl;

    if(clientData["type"] != "webauthn.get")
    {
        std::cerr << "clientdata type: " << clientData["type"] << " isn't set properly" << std::endl;
        return false;
    } 

    if(clientData["challenge"] != expectedChallenge)
    {
        std::cerr << "challenges don't match" << std::endl;
        return false;
    }

    if(clientData["origin"] != expectedOrigin)
    {
        std::cerr << "origin: " << clientData["origin"] << " != expected: " << expectedOrigin << std::endl;
        return false;
    }

    std::string authenticatorDataBase64Str = j["response"]["authenticatorData"];
    std::string authenticatorDataStr = decodeBase64Url(authenticatorDataBase64Str);
    AuthenticatorData authenticatorData = parseAuthenticatorData(std::vector<uint8_t>(authenticatorDataStr.begin(), authenticatorDataStr.end()));

    auto expectedRpIdSHA256 = sha256(expectedRpId);

    if(expectedRpIdSHA256 != authenticatorData.rpIdHash)
    {
        std::cerr << "auth data rpIdHash: ";
        for(auto b : authenticatorData.rpIdHash)
        {
            std::cerr << b;
        }
        std::cerr << " doesn't match expected rpId Sha256: ";
        for(auto b : expectedRpIdSHA256)
        {
            std::cerr << b;
        }
        std::cerr << std::endl;
        return false;
    }

    if(requireUserVerification && !authenticatorData.flags.uv())
    {
        std::cerr << "user verification was required, but wasn't verified during auth" << std::endl;
        return false;
    }

    if(
        (authenticatorData.signCount > 0 || credentialCurrentSignCount > 0) &&
        (authenticatorData.signCount <= credentialCurrentSignCount)
    )
    {
        std::cerr << "response sign count " << authenticatorData.signCount << " was not greater than current count of " << credentialCurrentSignCount << std::endl;
        return false;
    }

    auto clientDataHash = sha256(clientDataJSONStr);

    std::string signedData = authenticatorDataStr + bytesToString(clientDataHash);

    std::string signatureBase64Str = j["response"]["signature"];

    DecodedPublicKey* decodedCredentialPublicKey = nullptr;
    if(!decodeCredentialPublicKey(credentialPublicKey, &decodedCredentialPublicKey))
    {
        std::cerr << "failed to decode credential public key" << std::endl;
        return false;
    }

    //TODO this fails...
    bool verified = verifySignature(
        decodedCredentialPublicKey,
        decodeBase64Url(signatureBase64Str),
        signedData
    );

    if(!verified)
    {
        std::cerr << "could not verify authentication signature" << std::endl;
        return false;
    }

    bool isMultiDevice = authenticatorData.flags.be();
    bool isBackedUp = authenticatorData.flags.bs();

    if(!isMultiDevice && isBackedUp)
    {
        std::cerr << "Single device credential indicated that it was backed up, which should be impossible" << std::endl;
        return false;
    }

    std::string rawIdDecoded = decodeBase64Url(rawIdBase64Str);

    v = VerifiedAuthentication {
        std::vector<uint8_t>(rawIdDecoded.begin(), rawIdDecoded.end()),
        authenticatorData.signCount,
        isMultiDevice,
        isBackedUp,
        authenticatorData.flags.uv()
    };

    destroyPubKey(decodedCredentialPublicKey);

    return true;
}

}