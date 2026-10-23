#pragma once
#include <cstddef>
#include <cstdint>
#include <string>

// Original K95 RGB (VID 1B1C, PID 1B11), NXP report 03, 64 bytes.
// These are input-bit positions, NOT LED indices or Windows scan codes.
// Protocol references and source revisions are in REFERENCES.txt.
namespace k95 {
// Windows interface numbers vary. The user's K95 uses MI_00/COL03;
// other K95 layouts use MI_01/COL03. Match device and collection tokens.
inline std::wstring lower_ascii(std::wstring s) {
    for(auto& c:s) if(c>=L'A' && c<=L'Z') c+=L'a'-L'A';
    return s;
}
inline bool path_token(const std::wstring& path,const std::wstring& token) {
    std::size_t pos=0;
    while((pos=path.find(token,pos))!=std::wstring::npos) {
        auto end=pos+token.size();
        if((pos==0 || path[pos-1]==L'&' || path[pos-1]==L'#')
            && (end==path.size() || path[end]==L'&' || path[end]==L'#')) return true;
        ++pos;
    }
    return false;
}
inline bool target_path(const std::wstring& path) {
    auto p=lower_ascii(path);
    return path_token(p,L"vid_1b1c") && path_token(p,L"pid_1b11");
}
inline bool input_collection(const std::wstring& path) {
    return target_path(path) && path_token(lower_ascii(path),L"col03");
}
constexpr unsigned bits[18] = {
    120,121,122,123,124,125,126,127,128,129,
    136,137,138,139,140,141,142,143
};
inline bool decode(const unsigned char* data, std::size_t length, uint32_t& mask) {
    if (!data || length != 64 || data[0] != 3) return false;
    mask = 0;
    for (unsigned i=0; i<18; ++i)
        if (data[1+bits[i]/8] & (1u << (bits[i]%8))) mask |= 1u << i;
    return true;
}
inline bool decode_input(const std::wstring& path,const unsigned char* data,
                         std::size_t length,uint32_t& mask) {
    return input_collection(path) && decode(data,length,mask);
}
inline bool valid_batch(std::size_t available, uint32_t size, uint32_t count) {
    return size && count && size <= 4096 && count <= available / size;
}
struct Tracker {
    uint32_t held=0, down=0, complete=0;
    uint32_t pressed=0, released=0;
    void update(uint32_t next) {
        pressed = next & ~held;
        released = held & ~next;
        down |= pressed;
        complete |= released & down;
        held = next;
    }
};
}
