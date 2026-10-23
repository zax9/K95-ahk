#ifndef UNICODE
#define UNICODE
#endif
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <setupapi.h>
extern "C" {
#include <hidsdi.h>
#include <hidpi.h>
}
#include <tlhelp32.h>
#include <commdlg.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <iomanip>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <vector>
#include "decoder.h"

// Passive diagnostic. No SDK, output/feature reports, hooks, injected keys,
// service changes, registry writes, network calls, or driver installation.
// A WM_INPUT registration can cover other devices in the same usage class;
// ProcessRaw rejects all paths except VID_1B1C/PID_1B11 before reading payloads.
namespace {
constexpr wchar_t VERSION[]=L"K95 Diagnostic v0.2";
constexpr size_t MAX_LOG_CHARS=2*1024*1024;
constexpr UINT TIMER_ID=1;
constexpr int ID_SCAN=101, ID_START=102, ID_STOP=103, ID_SAVE=104;
HWND window=nullptr, status=nullptr, hint=nullptr, events=nullptr;
HWND scanButton=nullptr, startButton=nullptr, stopButton=nullptr, saveButton=nullptr;
std::array<HWND,18> cells{};
HFONT font=nullptr, monoFont=nullptr;
HBRUSH greenBrush=nullptr, blueBrush=nullptr, neutralBrush=nullptr;
int dpi=96;
bool capturing=false, haveCapture=false, contaminated=false, processUnknown=false;
bool reportSaved=false;
bool scanUnknown=false, logFull=false, dirty=false;
ULONGLONG started=0, checkedAt=0, paintedAt=0;
unsigned long long rawReports=0, directReports=0, keyboardEvents=0, decodedReports=0;
std::wstring logText, recentText, backgroundState;
unsigned backgroundCount=0;
std::map<std::wstring,k95::Tracker> trackers;
std::map<HANDLE,std::wstring> rawPaths;
std::map<std::wstring,unsigned> reportSamples;
struct StreamStats { unsigned long long reports=0,decoded=0; };
std::map<std::wstring,StreamStats> streamStats;
std::set<std::pair<USHORT,USHORT>> registeredUsages;
std::set<std::wstring> targetPaths;
uint32_t heldBits=0, completeBits=0, downBits=0;

struct Reader {
    HANDLE handle=INVALID_HANDLE_VALUE;
    OVERLAPPED ov{};
    std::vector<unsigned char> bytes;
    std::wstring path;
    bool pending=false, failed=false;
    ~Reader() {
        // Do not release an OVERLAPPED or its buffer until cancellation completes.
        if (handle!=INVALID_HANDLE_VALUE) {
            if (pending) {
                CancelIoEx(handle,&ov);
                DWORD ignored=0;
                GetOverlappedResult(handle,&ov,&ignored,TRUE);
            }
            CloseHandle(handle);
        }
        if (ov.hEvent) CloseHandle(ov.hEvent);
    }
};
std::vector<std::unique_ptr<Reader>> readers;

int S(int x) { return MulDiv(x,dpi,96); }
std::wstring lower(std::wstring s) {
    std::transform(s.begin(),s.end(),s.begin(),[](wchar_t c){return std::towlower(c);});
    return s;
}
bool corsair(const std::wstring& p) { return lower(p).find(L"vid_1b1c")!=std::wstring::npos; }
bool target(const std::wstring& p) {
    return k95::target_path(p);
}
bool inputCollection(const std::wstring& p) {
    return k95::input_collection(p);
}
std::wstring number(unsigned long long n) { return std::to_wstring(n); }
std::wstring hex(unsigned long long n, unsigned width=4) {
    std::wostringstream o; o<<std::hex<<std::uppercase<<std::setfill(L'0')<<std::setw(width)<<n; return o.str();
}
std::wstring error(DWORD n=GetLastError()) { return L"Win32 error "+number(n); }
std::wstring stamp(bool filename=false) {
    SYSTEMTIME t; GetLocalTime(&t); wchar_t b[80];
    if (filename) swprintf(b,80,L"%04u%02u%02u_%02u%02u%02u_%03u",t.wYear,t.wMonth,t.wDay,t.wHour,t.wMinute,t.wSecond,t.wMilliseconds);
    else swprintf(b,80,L"%04u-%02u-%02u %02u:%02u:%02u.%03u",t.wYear,t.wMonth,t.wDay,t.wHour,t.wMinute,t.wSecond,t.wMilliseconds);
    return b;
}
void log(const std::wstring& s, bool display=true) {
    auto line=stamp()+L"  "+s+L"\r\n";
    if (!logFull) {
        if (logText.size()+line.size()>MAX_LOG_CHARS) {
            logText+=L"LOG LIMIT REACHED. Additional detail omitted; key tracking continues.\r\n";
            logFull=true;
        } else logText+=line;
    }
    if (display) {
        recentText+=line;
        if (recentText.size()>12000) {
            auto pos=recentText.find(L'\n',recentText.size()-10000);
            if (pos!=std::wstring::npos) recentText.erase(0,pos+1);
        }
        dirty=true;
    }
}
void merge() {
    heldBits=completeBits=downBits=0;
    for (const auto& entry:trackers) {
        heldBits|=entry.second.held;
        completeBits|=entry.second.complete;
        downBits|=entry.second.down;
    }
}
unsigned completed() {
    unsigned n=0;
    for(unsigned i=0;i<18;++i) if(completeBits&(1u<<i)) ++n;
    return n;
}
bool relevantName(const std::wstring& name) {
    auto n=lower(name);
    return n.find(L"corsair")!=std::wstring::npos || n.find(L"icue")!=std::wstring::npos || n==L"cue.exe";
}
void checkBackground() {
    std::set<std::wstring> found; bool unknown=false;
    HANDLE snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(snapshot==INVALID_HANDLE_VALUE) { unknown=true; found.insert(L"Process scan failed: "+error()); }
    else {
        PROCESSENTRY32 pe{}; pe.dwSize=sizeof(pe);
        if(Process32First(snapshot,&pe)) {
            do { if(relevantName(pe.szExeFile)) found.insert(L"Process: "+std::wstring(pe.szExeFile)+L" PID="+number(pe.th32ProcessID)); }
            while(Process32Next(snapshot,&pe));
            if(GetLastError()!=ERROR_NO_MORE_FILES) unknown=true;
        } else unknown=true;
        CloseHandle(snapshot);
    }
    SC_HANDLE scm=OpenSCManager(nullptr,nullptr,SC_MANAGER_ENUMERATE_SERVICE);
    if(!scm) { unknown=true; found.insert(L"Service scan failed: "+error()); }
    else {
        DWORD resume=0;
        for(unsigned page=0;page<100;++page) {
            std::vector<unsigned char> buffer(256*1024);
            DWORD needed=0,count=0;
            BOOL ok=EnumServicesStatusEx(scm,SC_ENUM_PROCESS_INFO,SERVICE_WIN32,SERVICE_ACTIVE,
                buffer.data(),static_cast<DWORD>(buffer.size()),&needed,&count,&resume,nullptr);
            DWORD err=ok?ERROR_SUCCESS:GetLastError();
            if(!ok && err!=ERROR_MORE_DATA) { unknown=true; found.insert(L"Service scan failed: "+error(err)); break; }
            auto list=reinterpret_cast<ENUM_SERVICE_STATUS_PROCESS*>(buffer.data());
            for(DWORD i=0;i<count;++i)
                if(relevantName(list[i].lpServiceName)||relevantName(list[i].lpDisplayName))
                    found.insert(L"Active service: "+std::wstring(list[i].lpServiceName)+L" ("+list[i].lpDisplayName+L") state="+number(list[i].ServiceStatusProcess.dwCurrentState));
            if(ok) break;
            if(page==99) unknown=true;
        }
        CloseServiceHandle(scm);
    }
    std::wstring state;
    for(const auto& item:found) state+=item+L"\r\n";
    if(state.empty()) state=L"No named Corsair/iCUE processes or active services found.\r\n";
    if(state!=backgroundState || unknown!=processUnknown) log(L"Background check:\r\n"+state);
    backgroundState=state; processUnknown=unknown;
    backgroundCount=static_cast<unsigned>(found.size());
    if(capturing && (backgroundCount || unknown)) contaminated=true;
    checkedAt=GetTickCount64();
}
std::wstring devicePath(HANDLE h) {
    UINT size=0;
    if(GetRawInputDeviceInfo(h,RIDI_DEVICENAME,nullptr,&size)==static_cast<UINT>(-1) || size==0 || size>32768) return L"";
    std::vector<wchar_t> text(size+1,0);
    if(GetRawInputDeviceInfo(h,RIDI_DEVICENAME,text.data(),&size)==static_cast<UINT>(-1)) return L"";
    return text.data();
}
void registerUsage(USHORT page,USHORT usage) {
    if(!page || !usage || registeredUsages.count({page,usage})) return;
    RAWINPUTDEVICE rid{page,usage,RIDEV_INPUTSINK|RIDEV_DEVNOTIFY,window};
    if(RegisterRawInputDevices(&rid,1,sizeof(rid))) {
        registeredUsages.insert({page,usage});
        log(L"Raw Input registered: page="+hex(page)+L" usage="+hex(usage),false);
    } else { scanUnknown=true; log(L"Raw Input registration failed: page="+hex(page)+L" usage="+hex(usage)+L" "+error()); }
}
void enumerateRaw() {
    UINT count=0;
    if(GetRawInputDeviceList(nullptr,&count,sizeof(RAWINPUTDEVICELIST))!=0 || count>65536) {
        scanUnknown=true; log(L"Raw Input enumeration failed: "+error()); return;
    }
    if(!count) return;
    std::vector<RAWINPUTDEVICELIST> list(count);
    UINT result=GetRawInputDeviceList(list.data(),&count,sizeof(RAWINPUTDEVICELIST));
    if(result==static_cast<UINT>(-1)) { scanUnknown=true; log(L"Raw Input enumeration failed: "+error()); return; }
    for(UINT i=0;i<result;++i) {
        auto path=devicePath(list[i].hDevice);
        if(!corsair(path)) continue;
        RID_DEVICE_INFO info{}; info.cbSize=sizeof(info); UINT sz=sizeof(info);
        if(GetRawInputDeviceInfo(list[i].hDevice,RIDI_DEVICEINFO,&info,&sz)==static_cast<UINT>(-1)) {
            scanUnknown=true; log(L"Cannot read Raw Input metadata: "+error()); continue;
        }
        log(L"RAW interface: "+path+L" type="+number(info.dwType),false);
        if(!target(path)) continue;
        rawPaths[list[i].hDevice]=path; targetPaths.insert(lower(path));
        if(info.dwType==RIM_TYPEKEYBOARD) registerUsage(1,6);
        else if(info.dwType==RIM_TYPEHID) registerUsage(info.hid.usUsagePage,info.hid.usUsage);
    }
}
void enumerateHid(bool openReaders) {
    GUID guid; HidD_GetHidGuid(&guid);
    HDEVINFO set=SetupDiGetClassDevs(&guid,nullptr,nullptr,DIGCF_PRESENT|DIGCF_DEVICEINTERFACE);
    if(set==INVALID_HANDLE_VALUE) { scanUnknown=true; log(L"HID enumeration failed: "+error()); return; }
    for(DWORD i=0;i<1024;++i) {
        SP_DEVICE_INTERFACE_DATA di{}; di.cbSize=sizeof(di);
        if(!SetupDiEnumDeviceInterfaces(set,nullptr,&guid,i,&di)) {
            if(GetLastError()!=ERROR_NO_MORE_ITEMS) { scanUnknown=true; log(L"HID enumeration incomplete: "+error()); }
            break;
        }
        DWORD needed=0;
        SetupDiGetDeviceInterfaceDetail(set,&di,nullptr,0,&needed,nullptr);
        if(needed<sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA)||needed>65536) continue;
        std::vector<unsigned char> memory(needed);
        auto detail=reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA*>(memory.data());
        detail->cbSize=sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);
        if(!SetupDiGetDeviceInterfaceDetail(set,&di,detail,needed,nullptr,nullptr)) continue;
        std::wstring path=detail->DevicePath;
        if(!corsair(path)) continue;
        log(L"HID interface: "+path,false);
        HANDLE h=CreateFile(path.c_str(),0,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,0,nullptr);
        if(h==INVALID_HANDLE_VALUE) { log(L"  Metadata open failed: "+error(),false); continue; }
        HIDD_ATTRIBUTES attr{}; attr.Size=sizeof(attr);
        HIDP_CAPS caps{}; PHIDP_PREPARSED_DATA prep=nullptr;
        bool attrOk=HidD_GetAttributes(h,&attr)!=FALSE;
        bool capsOk=false;
        if(HidD_GetPreparsedData(h,&prep)) {
            capsOk=HidP_GetCaps(prep,&caps)==HIDP_STATUS_SUCCESS;
            HidD_FreePreparsedData(prep);
        }
        CloseHandle(h);
        if(attrOk) log(L"  VID="+hex(attr.VendorID)+L" PID="+hex(attr.ProductID)+L" bcdDevice="+hex(attr.VersionNumber),false);
        if(capsOk) log(L"  Usage page="+hex(caps.UsagePage)+L" usage="+hex(caps.Usage)+L" inputBytes="+number(caps.InputReportByteLength)+L" outputBytes="+number(caps.OutputReportByteLength)+L" featureBytes="+number(caps.FeatureReportByteLength),false);
        if(!target(path)||!attrOk||attr.VendorID!=0x1b1c||attr.ProductID!=0x1b11) continue;
        targetPaths.insert(lower(path));
        if(inputCollection(path)) log(L"G-key input collection found: "+path+L" (interface number is not restricted)");
        if(capsOk) registerUsage(caps.UsagePage,caps.Usage);
        if(!openReaders || !capsOk || caps.InputReportByteLength==0 || caps.InputReportByteLength>4096) continue;
        // Windows owns standard keyboard/mouse collections. Raw Input handles them.
        if(caps.UsagePage==1 && (caps.Usage==6||caps.Usage==2)) continue;
        auto reader=std::make_unique<Reader>(); reader->path=path;
        reader->handle=CreateFile(path.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,
            OPEN_EXISTING,FILE_FLAG_OVERLAPPED,nullptr);
        if(reader->handle==INVALID_HANDLE_VALUE) { log(L"Direct read open failed: "+path+L" "+error()); continue; }
        reader->ov.hEvent=CreateEvent(nullptr,TRUE,FALSE,nullptr);
        if(!reader->ov.hEvent) { log(L"Read event creation failed: "+error()); continue; }
        reader->bytes.resize(caps.InputReportByteLength);
        log(L"Direct read open: "+path+L" bytes="+number(caps.InputReportByteLength));
        readers.push_back(std::move(reader));
    }
    SetupDiDestroyDeviceInfoList(set);
}
void scan(bool openReaders) {
    rawPaths.clear(); targetPaths.clear(); scanUnknown=false;
    enumerateRaw(); enumerateHid(openReaders);
    log(L"K95 RGB interface paths found: "+number(targetPaths.size())+L"; direct readers: "+number(readers.size()));
    if(targetPaths.empty()) log(L"No original K95 RGB (VID 1B1C, PID 1B11) found. See interface details in the report.");
}
std::wstring bytesHex(const unsigned char* p,size_t n) {
    std::wstring s;
    for(size_t i=0;i<std::min<size_t>(n,128);++i) { if(i) s+=L' '; s+=hex(p[i],2); }
    if(n>128) s+=L" ...";
    return s;
}
void report(const std::wstring& route,const std::wstring& path,const unsigned char* p,size_t n) {
    if(!capturing||!target(path)||n==0) return;
    if(route==L"RAW") ++rawReports; else ++directReports;
    auto key=route+L" "+lower(path);
    auto& stats=streamStats[key]; ++stats.reports;
    // Keep at most 24 samples per interface, report ID, and report length.
    // Show the first two in the window as well as in the saved report.
    auto sampleKey=key+L" #"+number(p[0])+L" length="+number(n);
    auto& count=reportSamples[sampleKey];
    if(count<24) {
        log(route+L" sample "+path+L" length="+number(n)+L" data="+bytesHex(p,n),count<2);
        ++count;
    }
    uint32_t mask=0;
    if(!k95::decode_input(path,p,n,mask)) return;
    ++decodedReports; ++stats.decoded;
    auto& tracker=trackers[key]; tracker.update(mask);
    for(unsigned i=0;i<18;++i) {
        if(tracker.pressed&(1u<<i)) log(route+L" G"+number(i+1)+L" DOWN");
        if(tracker.released&(1u<<i)) log(route+L" G"+number(i+1)+L" UP");
    }
    merge();
}
void pollReaders() {
    if(!capturing) return;
    for(auto& r:readers) {
        if(r->failed) continue;
        // Bound the work per timer tick so the UI cannot be starved by input.
        for(unsigned pass=0;pass<32;++pass) {
            DWORD got=0;
            if(r->pending) {
                if(!GetOverlappedResult(r->handle,&r->ov,&got,FALSE)) {
                    DWORD e=GetLastError(); if(e==ERROR_IO_INCOMPLETE) break;
                    r->pending=false; r->failed=true;
                    log(L"Direct read failed: "+r->path+L" "+error(e)); break;
                }
                r->pending=false;
                if(got>0 && got<=r->bytes.size()) report(L"HID",r->path,r->bytes.data(),got);
                else { r->failed=true; log(L"Direct read returned an invalid byte count."); break; }
            }
            ResetEvent(r->ov.hEvent);
            if(ReadFile(r->handle,r->bytes.data(),static_cast<DWORD>(r->bytes.size()),&got,&r->ov)) {
                if(got>0 && got<=r->bytes.size()) report(L"HID",r->path,r->bytes.data(),got);
                else { r->failed=true; log(L"Direct read returned an invalid byte count."); break; }
            } else {
                DWORD e=GetLastError();
                if(e==ERROR_IO_PENDING) { r->pending=true; break; }
                r->failed=true; log(L"Direct read failed: "+r->path+L" "+error(e)); break;
            }
        }
    }
}
void processRaw(HRAWINPUT handle) {
    if(!capturing) return;
    RAWINPUTHEADER header{}; UINT sz=sizeof(header);
    if(GetRawInputData(handle,RID_HEADER,&header,&sz,sizeof(header))!=sizeof(header)) return;
    auto it=rawPaths.find(header.hDevice);
    if(it==rawPaths.end()) return; // Never capture payloads from other keyboards.
    UINT required=0;
    if(GetRawInputData(handle,RID_INPUT,nullptr,&required,sizeof(header))!=0 || required<sizeof(header)||required>1024*1024) return;
    std::vector<unsigned char> memory(required);
    UINT actual=GetRawInputData(handle,RID_INPUT,memory.data(),&required,sizeof(header));
    if(actual==static_cast<UINT>(-1)||actual!=required||actual<sizeof(header)) return;
    auto input=reinterpret_cast<RAWINPUT*>(memory.data());
    if(input->header.dwType==RIM_TYPEHID) {
        constexpr size_t start=offsetof(RAWINPUT,data)+offsetof(RAWHID,bRawData);
        if(actual<start) return;
        auto& hid=input->data.hid;
        if(!k95::valid_batch(actual-start,hid.dwSizeHid,hid.dwCount)) return;
        for(DWORD i=0;i<hid.dwCount;++i)
            report(L"RAW",it->second,hid.bRawData+static_cast<size_t>(i)*hid.dwSizeHid,hid.dwSizeHid);
    } else if(input->header.dwType==RIM_TYPEKEYBOARD && actual>=offsetof(RAWINPUT,data)+sizeof(RAWKEYBOARD)) {
        ++keyboardEvents;
        if(keyboardEvents<=40) {
            const auto& k=input->data.keyboard;
            log(L"K95 standard keyboard event: scan="+hex(k.MakeCode)+L" flags="+hex(k.Flags)+L" vk="+hex(k.VKey),keyboardEvents<=2);
        }
    }
}
std::wstring summary() {
    std::wstring text=std::wstring(VERSION)+L"\r\n";
    text+=L"Mode: passive; no configuration commands sent to the keyboard.\r\n";
    text+=L"Test state: "+std::wstring(capturing?L"RUNNING":haveCapture?L"STOPPED":L"NOT STARTED")+L"\r\n";
    text+=L"Keys with DOWN followed by UP: "+number(completed())+L" / 18\r\n";
    text+=L"Corsair background check during capture: "+std::wstring(!haveCapture?L"NOT TESTED":contaminated?L"NOT CLEAN OR INCOMPLETE":L"No named Corsair processes/services seen at sampled checks")+L"\r\n";
    text+=L"Checks identify names; they cannot prove the absence of every possible Corsair component.\r\n";
    text+=L"K95 Raw HID reports="+number(rawReports)+L"; direct HID reports="+number(directReports)
        +L"; decoded reports="+number(decodedReports)+L"; standard key events="+number(keyboardEvents)+L"\r\n";
    text+=L"Interface scan: "+std::wstring(scanUnknown?L"Some operations failed":L"Complete")+L"\r\n";
    text+=L"Decoder selection: VID 1B1C / PID 1B11 / COL03 on any interface; report ID 03; 64 bytes.\r\n";
    for(const auto& entry:streamStats)
        text+=entry.first+L": reports="+number(entry.second.reports)+L", decoded="+number(entry.second.decoded)+L"\r\n";
    for(unsigned i=0;i<18;++i)
        text+=L"G"+number(i+1)+L": "+((completeBits&(1u<<i))?L"DOWN + UP observed":(downBits&(1u<<i))?L"DOWN only":L"NOT OBSERVED")+L"\r\n";
    if(haveCapture&&decodedReports==0) text+=L"No supported G-key report was decoded. This does not prove that direct access is impossible. Input mode, firmware, report format, or Windows access may need further work.\r\n";
    text+=L"\r\nLatest background check:\r\n"+backgroundState;
    return text;
}
void refresh() {
    std::wstring top=L"Original K95 RGB  |  VID 1B1C / PID 1B11  |  "+number(targetPaths.size())+L" interfaces\r\n";
    top+=L"G keys: "+number(completed())+L" / 18 press-and-release pairs observed.  ";
    top+=capturing?L"TEST RUNNING":haveCapture?L"Test stopped":L"Ready";
    top+=L"\r\nCorsair background check: ";
    top+=processUnknown?L"INCOMPLETE":backgroundCount?L"RUNNING COMPONENTS FOUND":L"no named processes or active services found";
    if(contaminated) top+=L". Capture is not a clean iCUE-off test.";
    top+=L"\r\nRaw HID: "+number(rawReports)+L"   Direct HID: "+number(directReports)+L"   Decoded: "+number(decodedReports)+L"   Standard keys: "+number(keyboardEvents);
    SetWindowText(status,top.c_str());
    for(unsigned i=0;i<18;++i) {
        const wchar_t* state=(heldBits&(1u<<i))?L"DOWN":(completeBits&(1u<<i))?L"DOWN + UP":(downBits&(1u<<i))?L"UP missing":L"waiting";
        auto t=L"G"+number(i+1)+L"  "+state;
        SetWindowText(cells[i],t.c_str()); InvalidateRect(cells[i],nullptr,TRUE);
    }
    if(dirty) {
        SetWindowText(events,recentText.c_str());
        SendMessage(events,EM_SETSEL,static_cast<WPARAM>(-1),static_cast<LPARAM>(-1));
        SendMessage(events,EM_SCROLLCARET,0,0); dirty=false;
    }
    EnableWindow(startButton,!capturing && !haveCapture); EnableWindow(scanButton,!capturing);
    EnableWindow(stopButton,capturing); EnableWindow(saveButton,!capturing);
}
void stopCapture(const wchar_t* reason) {
    if(!capturing) return;
    checkBackground(); capturing=false;
    readers.clear();
    log(L"Capture stopped: "+std::wstring(reason)+L". Complete G keys: "+number(completed())+L" / 18.");
    log(L"Capture totals: Raw HID="+number(rawReports)+L"; Direct HID="+number(directReports)+L"; Decoded="+number(decodedReports)+L"; Standard keys="+number(keyboardEvents));
    for(const auto& entry:streamStats)
        log(L"Stream totals: "+entry.first+L" reports="+number(entry.second.reports)+L" decoded="+number(entry.second.decoded));
    if(!rawReports && !directReports) log(L"No HID reports arrived through either input method. Check Standard keys and save the full report.");
    else if(!decodedReports) log(L"HID reports arrived, but none matched the G-key collection and format. Save the full report for analysis.");
    else if(!downBits) log(L"Supported reports arrived, but no G-key press bits were set. Save the full report for analysis.");
    for(auto& item:trackers) item.second.held=0;
    merge(); refresh();
}
void startCapture() {
    checkBackground();
    if(backgroundCount||processUnknown) {
        MessageBox(window,L"The background check found Corsair components, or a check failed.\n\nExit iCUE. Stop the listed Corsair services. Then click Rescan.\n\nUse Save report to view the process and service names.",VERSION,MB_OK|MB_ICONINFORMATION);
        return;
    }
    if(haveCapture) {
        MessageBox(window,L"This window keeps one test. Save its report, then close and reopen the program for another test.",VERSION,MB_OK); return;
    }
    trackers.clear(); reportSamples.clear(); streamStats.clear(); rawReports=directReports=keyboardEvents=decodedReports=0;
    completeBits=heldBits=downBits=0; contaminated=false;
    capturing=true; haveCapture=true; reportSaved=false; started=GetTickCount64();
    log(L"CAPTURE START. Press and release A once, then G1 through G18. Capture stops after 120 seconds.");
    scan(true); pollReaders(); refresh();
}
bool saveReport() {
    wchar_t path[32768]{};
    auto name=L"K95_Diagnostic_v0_2_"+stamp(true)+L".txt";
    wcsncpy(path,name.c_str(),32767);
    OPENFILENAME ofn{}; ofn.lStructSize=sizeof(ofn); ofn.hwndOwner=window;
    ofn.lpstrFilter=L"Text report (*.txt)\0*.txt\0\0"; ofn.lpstrFile=path; ofn.nMaxFile=32768;
    ofn.Flags=OFN_PATHMUSTEXIST|OFN_NOCHANGEDIR; ofn.lpstrDefExt=L"txt";
    if(!GetSaveFileName(&ofn)) return false;
    auto text=summary()+L"\r\n--- Device details and captured events ---\r\n"+logText;
    int n=WideCharToMultiByte(CP_UTF8,0,text.c_str(),static_cast<int>(text.size()),nullptr,0,nullptr,nullptr);
    if(n<=0) { MessageBox(window,L"Could not encode the report.",VERSION,MB_OK|MB_ICONERROR); return false; }
    std::string bytes(static_cast<size_t>(n),'\0');
    WideCharToMultiByte(CP_UTF8,0,text.c_str(),static_cast<int>(text.size()),&bytes[0],n,nullptr,nullptr);
    HANDLE file=CreateFile(path,GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(file==INVALID_HANDLE_VALUE) {
        auto msg=L"Could not create the report. Existing files are not replaced.\nChoose a new name or another folder.\n"+error();
        MessageBox(window,msg.c_str(),VERSION,MB_OK|MB_ICONERROR); return false;
    }
    DWORD written=0; BOOL ok=WriteFile(file,bytes.data(),static_cast<DWORD>(bytes.size()),&written,nullptr);
    DWORD failure=ok?ERROR_SUCCESS:GetLastError();
    if(ok && written==bytes.size()) { if(!FlushFileBuffers(file)) { ok=FALSE; failure=GetLastError(); } }
    CloseHandle(file);
    if(!ok || written!=bytes.size()) {
        auto msg=L"Report write failed or was incomplete. "+error(failure);
        MessageBox(window,msg.c_str(),VERSION,MB_OK|MB_ICONERROR);
        return false;
    } else {
        auto msg=L"Report saved:\n"+std::wstring(path);
        MessageBox(window,msg.c_str(),VERSION,MB_OK|MB_ICONINFORMATION);
        reportSaved=true;
        return true;
    }
}
HWND control(const wchar_t* cls,const wchar_t* text,DWORD style,int x,int y,int w,int h,int id=0) {
    HWND c=CreateWindowEx(0,cls,text,WS_CHILD|WS_VISIBLE|style,S(x),S(y),S(w),S(h),window,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),GetModuleHandle(nullptr),nullptr);
    SendMessage(c,WM_SETFONT,reinterpret_cast<WPARAM>(font),TRUE); return c;
}
LRESULT CALLBACK windowProc(HWND h,UINT msg,WPARAM wp,LPARAM lp) {
    switch(msg) {
    case WM_CREATE: {
        window=h;
        font=CreateFont(-S(15),0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");
        monoFont=CreateFont(-S(13),0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,FIXED_PITCH,L"Consolas");
        greenBrush=CreateSolidBrush(RGB(214,243,223)); blueBrush=CreateSolidBrush(RGB(208,231,255)); neutralBrush=CreateSolidBrush(RGB(237,239,242));
        status=control(L"STATIC",L"Checking devices...",0,16,14,862,104);
        hint=control(L"STATIC",L"Exit iCUE and stop its Corsair services. Click Start test. Press A once, then press and release each G key.\r\nThis test only reads input. Report samples can include other keys pressed during the test.",0,16,120,862,48);
        for(unsigned i=0;i<18;++i) cells[i]=control(L"STATIC",L"waiting",SS_CENTER|SS_CENTERIMAGE|WS_BORDER,
            16+static_cast<int>(i%6)*145,180+static_cast<int>(i/6)*44,136,34);
        scanButton=control(L"BUTTON",L"Rescan",WS_TABSTOP|BS_PUSHBUTTON,16,322,120,32,ID_SCAN);
        startButton=control(L"BUTTON",L"Start test",WS_TABSTOP|BS_PUSHBUTTON,148,322,120,32,ID_START);
        stopButton=control(L"BUTTON",L"Stop test",WS_TABSTOP|BS_PUSHBUTTON,280,322,120,32,ID_STOP);
        saveButton=control(L"BUTTON",L"Save report",WS_TABSTOP|BS_PUSHBUTTON,412,322,140,32,ID_SAVE);
        events=control(L"EDIT",L"",ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL|WS_VSCROLL|WS_BORDER,16,370,862,242);
        SendMessage(events,WM_SETFONT,reinterpret_cast<WPARAM>(monoFont),TRUE);
        log(VERSION); log(L"Windows pointer size: "+number(sizeof(void*)*8)+L" bits; timestamp uses local time.",false);
        typedef LONG(WINAPI *RtlVersion)(OSVERSIONINFOW*);
        RtlVersion rv=nullptr;
        auto proc=GetProcAddress(GetModuleHandle(L"ntdll.dll"),"RtlGetVersion");
        static_assert(sizeof(rv)==sizeof(proc),"Function pointer size");
        std::memcpy(&rv,&proc,sizeof(rv));
        if(rv) { OSVERSIONINFOW v{}; v.dwOSVersionInfoSize=sizeof(v); if(rv(&v)==0) log(L"Windows "+number(v.dwMajorVersion)+L"."+number(v.dwMinorVersion)+L" build "+number(v.dwBuildNumber),false); }
        checkBackground(); scan(false); refresh(); SetTimer(h,TIMER_ID,20,nullptr); return 0;
    }
    case WM_COMMAND:
        if(HIWORD(wp)==BN_CLICKED) switch(LOWORD(wp)) {
            case ID_SCAN: checkBackground(); scan(false); refresh(); break;
            case ID_START: startCapture(); break;
            case ID_STOP: stopCapture(L"user stopped test"); break;
            case ID_SAVE: saveReport(); break;
        }
        return 0;
    case WM_INPUT:
        processRaw(reinterpret_cast<HRAWINPUT>(lp));
        // DefWindowProc is required for foreground raw-input cleanup.
        return DefWindowProc(h,msg,wp,lp);
    case WM_INPUT_DEVICE_CHANGE:
        if(capturing) stopCapture(L"device list changed; restart the program after reconnecting the keyboard");
        return 0;
    case WM_TIMER: {
        if(wp!=TIMER_ID) break;
        ULONGLONG now=GetTickCount64();
        pollReaders();
        if(now-checkedAt>=2000) checkBackground();
        if(capturing && now-started>=120000) stopCapture(L"120-second limit");
        if(now-paintedAt>=250) { refresh(); paintedAt=now; }
        return 0;
    }
    case WM_CTLCOLORSTATIC:
        for(unsigned i=0;i<18;++i) if(reinterpret_cast<HWND>(lp)==cells[i]) {
            auto dc=reinterpret_cast<HDC>(wp);
            COLORREF color=(heldBits&(1u<<i))?RGB(208,231,255):(completeBits&(1u<<i))?RGB(214,243,223):RGB(237,239,242);
            SetBkColor(dc,color); SetTextColor(dc,RGB(20,32,45));
            return reinterpret_cast<LRESULT>((heldBits&(1u<<i))?blueBrush:(completeBits&(1u<<i))?greenBrush:neutralBrush);
        }
        break;
    case WM_CLOSE:
        stopCapture(L"window closed");
        if(haveCapture && !reportSaved) {
            int answer=MessageBox(h,L"Save the test report before closing?",VERSION,MB_YESNOCANCEL|MB_ICONQUESTION);
            if(answer==IDCANCEL) return 0;
            if(answer==IDYES && !saveReport()) return 0;
        }
        DestroyWindow(h); return 0;
    case WM_DESTROY:
        KillTimer(h,TIMER_ID); readers.clear();
        for(auto pair:registeredUsages) { RAWINPUTDEVICE rid{pair.first,pair.second,RIDEV_REMOVE,nullptr}; RegisterRawInputDevices(&rid,1,sizeof(rid)); }
        DeleteObject(font); DeleteObject(monoFont); DeleteObject(greenBrush); DeleteObject(blueBrush); DeleteObject(neutralBrush);
        PostQuitMessage(0); return 0;
    }
    return DefWindowProc(h,msg,wp,lp);
}
}
int WINAPI wWinMain(HINSTANCE instance,HINSTANCE,PWSTR,int show) {
    SetProcessDPIAware();
    HDC dc=GetDC(nullptr); if(dc) { dpi=GetDeviceCaps(dc,LOGPIXELSX); ReleaseDC(nullptr,dc); }
    WNDCLASS wc{}; wc.lpfnWndProc=windowProc; wc.hInstance=instance; wc.lpszClassName=L"K95DiagnosticV02";
    wc.hCursor=LoadCursor(nullptr,IDC_ARROW); wc.hbrBackground=reinterpret_cast<HBRUSH>(COLOR_BTNFACE+1);
    if(!RegisterClass(&wc)) return 1;
    RECT rect{0,0,S(896),S(630)};
    DWORD style=WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX;
    AdjustWindowRect(&rect,style,FALSE);
    HWND h=CreateWindow(wc.lpszClassName,VERSION,style,CW_USEDEFAULT,CW_USEDEFAULT,
        rect.right-rect.left,rect.bottom-rect.top,nullptr,nullptr,instance,nullptr);
    if(!h) return 2;
    ShowWindow(h,show); UpdateWindow(h);
    MSG msg{}; BOOL result;
    while((result=GetMessage(&msg,nullptr,0,0))>0) {
        if(!IsDialogMessage(h,&msg)) { TranslateMessage(&msg); DispatchMessage(&msg); }
    }
    return result<0?3:static_cast<int>(msg.wParam);
}
