#include <cstdio>
#include <cstring>
#include <cstdint>
#include "algorithm.h"

static int g_failures = 0;

static void check(bool ok, const char *name)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) {
        ++g_failures;
    }
}

int main()
{
    // Base64 正常编解码
    {
        basic::ByteBuffer in;
        basic::ByteBuffer encoded;
        basic::ByteBuffer decoded;
        in.write_bytes("hello", 5);

        ssize_t enc_len = algorithm::encode_base64(in, encoded);
        ssize_t dec_len = algorithm::decode_base64(encoded, decoded);
        check(enc_len == 8 && encoded.str() == "aGVsbG8=", "base64 encode");
        check(dec_len == 5 && decoded.str() == "hello", "base64 decode");
    }

    // Base64 非法输入必须拒绝
    {
        const char *bad_inputs[] = {"YQ==junk", "====", "Y", "YQ="};
        for (size_t i = 0; i < sizeof(bad_inputs) / sizeof(bad_inputs[0]); ++i) {
            basic::ByteBuffer in;
            basic::ByteBuffer out;
            in.write_bytes(bad_inputs[i], static_cast<ssize_t>(std::strlen(bad_inputs[i])));
            check(algorithm::decode_base64(in, out) == -1, bad_inputs[i]);
        }

        basic::ByteBuffer unpadded;
        basic::ByteBuffer out;
        unpadded.write_bytes("YQ", 2);
        check(algorithm::decode_base64(unpadded, out) == 1 && out.str() == "a",
              "base64 unpadded");
    }

    // SHA-1 空输入
    {
        const uint8_t expect[20] = {
            0xDA, 0x39, 0xA3, 0xEE, 0x5E, 0x6B, 0x4B, 0x0D, 0x32, 0x55,
            0xBF, 0xEF, 0x95, 0x60, 0x18, 0x90, 0xAF, 0xD8, 0x07, 0x09
        };
        basic::ByteBuffer in;
        basic::ByteBuffer out;
        uint8_t digest[20] = {0};
        ssize_t ret = algorithm::sha1(in, out);
        out.read_only(0, digest, sizeof(digest));
        check(ret == 0 && out.data_size() == 20 &&
              std::memcmp(digest, expect, sizeof(expect)) == 0, "sha1 empty");
    }

    return g_failures == 0 ? 0 : 1;
}
