#include "algorithm.h"

namespace algorithm {

char bs64[66] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
int encode_base64(basic::ByteBuffer &inbuf, basic::ByteBuffer &outbuf)
{
    ssize_t len = inbuf.data_size();
    if (len <= 0) {
        outbuf.clear();
        return 0;
    }
    int groups = len / 3;
    int remain = len - groups * 3;
    
    outbuf.clear();
    for (int i = 0; i < groups; ++i) {
        //(1) 0xFC: 1111 1100 >> 2 => 0011 1111
        outbuf += (inbuf[i * 3 + 0] & 0xFC) >> 2;
        //(1) 0xC0: 0000 0011 << 4 => 0011 0000  | (2) 0xF0: 1111 0000 >> 4 => 0000 1111 => 0011 1111
        outbuf += (inbuf[i * 3 + 0] & 0x03) << 4 | (inbuf[i * 3 + 1] & 0xF0) >> 4;
        //(2) 0x0F: 0000 1111 << 2 => 0011 1100  | (3) 0xC0: 1100 0000 >> 6 => 0000 0011 => 0011 1111 
        outbuf += (inbuf[i * 3 + 1] & 0x0F) << 2 | (inbuf[i * 3 + 2] & 0xC0) >> 6;
        //(3) 0x3F: 0011 1111 => 0011 1111
        outbuf += inbuf[i * 3 + 2] & 0x3F;
    }
    
    if (remain == 1) {
        //(1) 0xFC: 1111 1100 >> 2 => 0011 1111
        outbuf += (inbuf[groups * 3 + 0] & 0xFC) >> 2;
        //(1) 0xC0: 0000 0011 << 4 => 0011 0000  | (2) 0xF0: 1111 0000 >> 4 => 0000 1111 => 0011 1111
        outbuf += (inbuf[groups * 3 + 0] & 0x03) << 4;
        // 剩余的用 = 补齐
        outbuf += '=';
        outbuf += '=';
    }
    else if (remain == 2) {
        //(1) 0xFC: 1111 1100 >> 2 => 0011 1111
        outbuf += (inbuf[groups * 3 + 0] & 0xFC) >> 2;
        //(1) 0xC0: 0000 0011 << 4 => 0011 0000  | (2) 0xF0: 1111 0000 >> 4 => 0000 1111 => 0011 1111
        outbuf += (inbuf[groups * 3 + 0] & 0x03) << 4 | (inbuf[groups * 3 + 1] & 0xF0) >> 4;
        //(2) 0x0F: 0000 1111 << 2 => 0011 1100  | (3) 0xC0: 1100 0000 >> 6 => 0000 0011 => 0011 1111 
        outbuf += (inbuf[groups * 3 + 1] & 0x0F) << 2;
        // 剩余的用 = 补齐
        outbuf += '=';
    }

    // 需要转换的字节数，去除补齐的'='
    int covert_num = (remain == 0 ? outbuf.data_size() : outbuf.data_size() + remain - 3);
    for (int i = 0; i < covert_num; ++i)
    {
        outbuf[i] = bs64[outbuf[i]];
    }

    return outbuf.data_size();
}

int decode_base64(basic::ByteBuffer &inbuf, basic::ByteBuffer &outbuf)
{
    outbuf.clear();
    ssize_t len = inbuf.data_size();
    if (len <= 0) {
        return 0;
    }

    basic::ByteBuffer covbuf = inbuf;

    int i = 0, j = 0;
    for (i = 0; i < inbuf.data_size(); ++i) {
        if (inbuf[i] == '=') {
            break;
        }
        for (j = 0; j < 64; ++j) {
            if (inbuf[i] == bs64[j]) {
                break;
            }
        }
        covbuf[i] = j;
    }
    
    j = 0;
    int groups = i / 4;
    int remain = i - groups * 4;
    for (i = 0; i < groups; ++i) {
        outbuf[j++] = covbuf[i * 4 + 0] << 2 | (covbuf[i * 4 + 1] & 0x30) >> 4;
        outbuf[j++] = (covbuf[i * 4 + 1] & 0x0F) << 4 | (covbuf[i * 4 + 2] & 0x3C) >> 2;
        outbuf[j++] = (covbuf[i * 4 + 2] & 0x03) << 6 | (covbuf[i * 4 + 3] & 0x3F);
    }
    
    if (remain == 2) {
        outbuf[j++] = covbuf[groups * 4 + 0] << 2 | (covbuf[groups * 4 + 1] & 0x30) >> 4;
    } else if (remain == 3) {
        outbuf[j++] = covbuf[i * 4 + 0] << 2 | (covbuf[i * 4 + 1] & 0x30) >> 4;
        outbuf[j++] = (covbuf[i * 4 + 1] & 0x0F) << 4 | (covbuf[i * 4 + 2] & 0x3C) >> 2;
    }
    
    return j;
}

}