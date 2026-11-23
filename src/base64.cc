#include "algorithm.h"

#include <string>
#include <vector>

namespace algorithm {

namespace {

const char s_base64_alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int base64_value(unsigned char c)
{
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    }
    if (c == '+') {
        return 62;
    }
    if (c == '/') {
        return 63;
    }
    return -1;
}

} // namespace

ssize_t encode_base64(basic::ByteBuffer &inbuf, basic::ByteBuffer &outbuf)
{
    outbuf.clear();

    ssize_t len = inbuf.data_size();
    if (len <= 0) {
        return 0;
    }

    std::vector<unsigned char> input(static_cast<size_t>(len));
    ssize_t read_len = inbuf.read_only(0, input.data(), len);
    if (read_len <= 0) {
        return 0;
    }

    std::string encoded;
    encoded.reserve(static_cast<size_t>(((read_len + 2) / 3) * 4));

    ssize_t i = 0;
    for (; i + 3 <= read_len; i += 3) {
        uint32_t value = (static_cast<uint32_t>(input[i]) << 16) |
                         (static_cast<uint32_t>(input[i + 1]) << 8) |
                         static_cast<uint32_t>(input[i + 2]);
        encoded.push_back(s_base64_alphabet[(value >> 18) & 0x3F]);
        encoded.push_back(s_base64_alphabet[(value >> 12) & 0x3F]);
        encoded.push_back(s_base64_alphabet[(value >> 6) & 0x3F]);
        encoded.push_back(s_base64_alphabet[value & 0x3F]);
    }

    ssize_t remain = read_len - i;
    if (remain == 1) {
        uint32_t value = static_cast<uint32_t>(input[i]) << 16;
        encoded.push_back(s_base64_alphabet[(value >> 18) & 0x3F]);
        encoded.push_back(s_base64_alphabet[(value >> 12) & 0x3F]);
        encoded.push_back('=');
        encoded.push_back('=');
    } else if (remain == 2) {
        uint32_t value = (static_cast<uint32_t>(input[i]) << 16) |
                         (static_cast<uint32_t>(input[i + 1]) << 8);
        encoded.push_back(s_base64_alphabet[(value >> 18) & 0x3F]);
        encoded.push_back(s_base64_alphabet[(value >> 12) & 0x3F]);
        encoded.push_back(s_base64_alphabet[(value >> 6) & 0x3F]);
        encoded.push_back('=');
    }

    outbuf.write_bytes(encoded.data(), static_cast<ssize_t>(encoded.size()));
    return static_cast<ssize_t>(encoded.size());
}

ssize_t decode_base64(basic::ByteBuffer &inbuf, basic::ByteBuffer &outbuf)
{
    outbuf.clear();

    ssize_t len = inbuf.data_size();
    if (len <= 0) {
        return 0;
    }

    std::string input(static_cast<size_t>(len), '\0');
    ssize_t read_len = inbuf.read_only(0, &input[0], len);
    if (read_len <= 0) {
        return 0;
    }
    input.resize(static_cast<size_t>(read_len));

    std::string decoded;
    decoded.reserve(input.size() / 4 * 3 + 3);

    uint32_t value = 0;
    int bits = 0;
    for (size_t i = 0; i < input.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(input[i]);
        if (c == '=') {
            break;
        }
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') {
            continue;
        }

        int v = base64_value(c);
        if (v < 0) {
            return -1;
        }

        value = (value << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            decoded.push_back(static_cast<char>((value >> bits) & 0xFF));
        }
    }

    if (!decoded.empty()) {
        outbuf.write_bytes(decoded.data(), static_cast<ssize_t>(decoded.size()));
    }
    return static_cast<ssize_t>(decoded.size());
}

} // namespace algorithm
