#include "decoder.h"
#include <cassert>
#include <cstdio>
#include <cstring>

int main() {
    // Regression: real device paths from the user's v0.1 diagnostic output.
    const std::wstring mi00=L"\\\\?\\hid#vid_1b1c&pid_1b11&mi_00&col03#a&3803a396&0&0002#{4d1e55b2-f16f-11cf-88cb-001111000030}";
    const std::wstring mi01=L"\\\\?\\HID#VID_1B1C&PID_1B11&MI_01&COL03#a&test&0&0002#{4d1e55b2-f16f-11cf-88cb-001111000030}";
    const std::wstring control=L"\\\\?\\hid#vid_1b1c&pid_1b11&mi_01#a&20401751&0&0000#{4d1e55b2-f16f-11cf-88cb-001111000030}";
    assert(k95::input_collection(mi00));
    assert(k95::input_collection(mi01));
    assert(!k95::input_collection(control));
    assert(!k95::input_collection(L"hid#vid_1b1c&pid_1b11&mi_00&col04#test"));
    assert(!k95::input_collection(L"hid#vid_1b1c&pid_1b11&mi_00&col030#test"));
    assert(!k95::input_collection(L"hid#vid_1b1c&pid_1b110&mi_00&col03#test"));
    assert(!k95::input_collection(L"hid#vid_1234&pid_1b11&mi_00&col03#test"));
    assert(!k95::input_collection(L"hid#vid_1b1c&pid_1234&mi_00&col03#test"));
    // Independent wire examples: data[16]=G1..G8, [17] bits 0..1=G9..G10,
    // data[18]=G11..G18. The other six bits of data[17] are not G keys.
    for (unsigned i=0;i<18;++i) {
        unsigned char r[64]={3};
        unsigned byte = i<8 ? 16 : i<10 ? 17 : 18;
        unsigned bit = i<8 ? i : i<10 ? i-8 : i-10;
        r[byte] = static_cast<unsigned char>(1u<<bit);
        uint32_t m=0;
        assert(k95::decode(r,64,m) && m==(1u<<i));
        // Exercise the complete path-selection + packet-decoding gate.
        assert(k95::decode_input(mi00,r,64,m) && m==(1u<<i));
        assert(k95::decode_input(mi01,r,64,m) && m==(1u<<i));
        assert(!k95::decode_input(control,r,64,m));
        assert(!k95::decode_input(mi00,r,63,m));
        k95::Tracker t;
        t.update(m); assert(t.pressed==m && t.complete==0);
        t.update(m); assert(t.pressed==0 && t.released==0);
        t.update(0); assert(t.released==m && t.complete==m);
    }
    unsigned char r[64]={3}; uint32_t m=99;
    assert(!k95::decode(nullptr,64,m));
    for (unsigned n=0;n<64;++n) assert(!k95::decode(r,n,m));
    assert(!k95::decode(r,65,m));
    r[0]=1; assert(!k95::decode(r,64,m));
    r[0]=3; r[17]=0xfc;
    assert(k95::decode(r,64,m) && m==0);
    r[16]=0xff; r[17]=0xff; r[18]=0xff;
    assert(k95::decode(r,64,m) && m==0x3ffff);
    k95::Tracker t; t.update(0x20001); t.update(0x20000);
    assert(t.complete==1 && t.held==0x20000);
    t.update(0); assert(t.complete==0x20001);
    assert(k95::valid_batch(128,64,2));
    assert(!k95::valid_batch(127,64,2));
    assert(!k95::valid_batch(64,0,1));
    assert(!k95::valid_batch(64,64,0));
    assert(!k95::valid_batch(128,0xffffffff,0xffffffff));
    assert(!k95::valid_batch(128,64,0xffffffff));
    std::puts("PASS: MI_00 and MI_01 path regressions; unrelated collection/device rejection; all 18 keys through the full path/report gate; transitions; invalid packets; batch bounds.");
}
