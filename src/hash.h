#pragma once

#include <iostream>

namespace hash::base64 {

std::string encode(const void *data, size_t size);
std::vector<unsigned char> decode(const std::string& str);


} // namespace hash::base64
