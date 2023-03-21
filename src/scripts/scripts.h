#include <cstdint>

namespace scripts {

bool inject_create_remote_thread(uint32_t pid);
bool inject_create_process_hollowed(const std::wstring& original_image, const std::wstring& injected_image);

}