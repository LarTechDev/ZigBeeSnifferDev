#include <iostream>
#include <windows.h>
#include <unistd.h>
#include <math.h>  //USED FOR CEIL
#include <chrono>  //Used for System Time
#include <fstream> //USED for File Handling
#include <stdio.h>

#include "WireSharkSerialAdapter.h"

using namespace std;

static string Port                  = DEFAULT_SERIAL_PORT;
static string BaudRate              = DEFAULT_BAUND_RATE;
static string ByteSize              = DEFAULT_BYTE_SIZE;
static string StopBits              = DEFAULT_STOP_BITS;
static string Parity                = DEFAULT_PARITY;
static string Channel               = DEFAULT_CHANNEL;
static string FrameDelay            = DEFAULT_FRAME_DELAY;

static HANDLE hComSerial            = INVALID_HANDLE_VALUE;
static HANDLE hCommReadThread       = INVALID_HANDLE_VALUE;
static HANDLE hCommFrameReadyEvent  = INVALID_HANDLE_VALUE;
static HANDLE hCommFrameQueuedEvent = INVALID_HANDLE_VALUE;
static HANDLE hControlInThread      = INVALID_HANDLE_VALUE;    
static HANDLE hControlInEvent       = INVALID_HANDLE_VALUE;
static HANDLE hCaptureOutputPipe    = INVALID_HANDLE_VALUE; /* pipe handle */
static HANDLE hControlInPipe        = INVALID_HANDLE_VALUE; /* pipe handle */    
static HANDLE hControlOutPipe       = INVALID_HANDLE_VALUE; /* pipe handle */

static string CaptureOutputPipeName = "";
static string ControlInPipeName     = "";
static string ControlOutPipeName    = "";

typeFrameVector SerialFrameVector;

DWORD WINAPI 
ComReadThreadFunc(LPVOID lpParam) {
    string mPORT("\\\\.\\COM" + Port);

    DWORD mBaudRate = stoi(BaudRate);
    BYTE  mByteSize = stoi(ByteSize);

    BYTE mStopBits;
    if (StopBits.compare("1") == 0) {
        mStopBits = ONESTOPBIT;
    } else {
        mStopBits = TWOSTOPBITS;
    }

    BYTE mParity;
    if (Parity.compare("NONE") == 0) {
        mParity = NOPARITY;
    }
    if (Parity.compare("ODD") == 0) {
        mParity = ODDPARITY;
    } else
    if (Parity.compare("EVEN") == 0) {
        mParity = EVENPARITY;
    } else {
        mParity = NOPARITY;
    }

    hComSerial = CreateFileA(mPORT.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 
                             NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    // Do some basic settings
    BOOL fSuccess;
    DCB serialParams       = { 0 };
    serialParams.DCBlength = sizeof(DCB);
    fSuccess               = GetCommState(hComSerial, &serialParams);

    serialParams.BaudRate          = mBaudRate;
    serialParams.ByteSize          = mByteSize;;
    serialParams.Parity            = mParity;
    serialParams.StopBits          = mStopBits;
    serialParams.fOutxCtsFlow      = false;
    serialParams.fOutxDsrFlow      = false;
    serialParams.fDtrControl       = 0;
    serialParams.fDsrSensitivity   = false;
    serialParams.fTXContinueOnXoff = false;
    serialParams.fOutX             = false;
    serialParams.fInX              = false;
    serialParams.fNull             = false;
    serialParams.fRtsControl       = 0;

    fSuccess = SetCommState(hComSerial, &serialParams);
    GetCommState(hComSerial, &serialParams);

    // Set timeouts 
    COMMTIMEOUTS timeout                = { 0 };
    timeout.ReadIntervalTimeout         = MAXDWORD; 
    timeout.ReadTotalTimeoutMultiplier  = MAXDWORD;
    timeout.ReadTotalTimeoutConstant    = 1;
    timeout.WriteTotalTimeoutMultiplier = 0;
    timeout.WriteTotalTimeoutConstant   = 0;
    SetCommTimeouts(hComSerial, &timeout);

    typeFrameByte RX_CHAR[UART_BUFFER_SIZE];
    int RX_LEN;
    DWORD dwCommEvent;

    if (!SetCommMask(hComSerial, EV_RXCHAR));   // Error setting communications event mask.
    PurgeComm(hComSerial, PURGE_RXCLEAR|PURGE_TXCLEAR);
    ReadFile(hComSerial, &RX_CHAR, UART_BUFFER_SIZE - 1, (LPDWORD)((void *)&RX_LEN), NULL);
    
    bool SeccessfullyReadin;
    double EV_Timeout = 0;
    LARGE_INTEGER freq, start, end;

    // Sende set_channel command (0xCA - command-code)
    typeFrameByte SetChannelCommand[2] = {0xCA, (BYTE)((Channel[0] - 0x30) * 10 + (Channel[1] - 0x30))};
    WriteFile(hComSerial, &SetChannelCommand, 2, NULL, NULL);

    double ReadTimeOut = stod(FrameDelay);
    while(hComSerial != INVALID_HANDLE_VALUE) {
        if (WaitCommEvent(hComSerial, &dwCommEvent, NULL)) { 
            do {
                RX_LEN = 0;
                SeccessfullyReadin = ReadFile(hComSerial, &RX_CHAR, UART_BUFFER_SIZE - 1, 
                                              (LPDWORD)((void *)&RX_LEN), NULL);
                if (RX_LEN > 0 && SeccessfullyReadin) {
                    // A Data has been read; process it.
                    SerialFrameVector.insert(SerialFrameVector.end(), RX_CHAR, RX_CHAR + RX_LEN);
                    QueryPerformanceCounter(&start);
                    EV_Timeout = 0;
                } else {
                    usleep(static_cast<useconds_t>(ReadTimeOut / 2)); /* Wait half the readtimeout to free CPU 
                                                                         resource and wait for more data to be 
                                                                         recieved */
                    QueryPerformanceFrequency(&freq);
                    QueryPerformanceCounter(&end);
                    // subtract before dividing to improve precision
                    EV_Timeout = static_cast<double>(end.QuadPart - start.QuadPart) / 
                                 static_cast<double>(freq.QuadPart / 1000000);
                }
            } while(EV_Timeout < ReadTimeOut);
            
            if(!SerialFrameVector.empty()) {                
                SetEvent(hCommFrameReadyEvent);                       // Send Frame to be buffered to Queue
                WaitForSingleObject(hCommFrameQueuedEvent, INFINITE); // indefinite wait for event frame Queue Event 
                ResetEvent(hCommFrameQueuedEvent);
                SerialFrameVector.clear();
            }
        }
    }
    return 0;
}

int 
CreateComThread() {
    int CreateStatus = 0;

    hCommReadThread       = CreateThread(NULL, 0, ComReadThreadFunc, NULL, 0, NULL);
    hCommFrameQueuedEvent = CreateEvent(NULL, TRUE, FALSE, TEXT("FrameQueuedEvent")); 
    hCommFrameReadyEvent  = CreateEvent(NULL, TRUE, FALSE, TEXT("CommFrameReadyEvent")); 

    if (hCommReadThread == INVALID_HANDLE_VALUE || hCommFrameReadyEvent  == INVALID_HANDLE_VALUE || 
                  hCommReadThread       == NULL || hCommFrameReadyEvent  == NULL || 
                  hCommFrameQueuedEvent == NULL || hCommFrameQueuedEvent == NULL) {
        cout<<"Creating Thread Error";
        CloseHandle(hCommReadThread);
        CloseHandle(hCommFrameReadyEvent);
        CloseHandle(hCommFrameQueuedEvent);
    } else {
        CreateStatus = 1;
    }

    return(CreateStatus);
}

typeFrameVector 
WireSharkPacket(typeFrameByte  frame[], int len) {
    static bool     xHeaderWritten = false;
    typeFrameVector OutVector;
    typeFrameByte   *ptr;

    if (!xHeaderWritten) {
        xHeaderWritten = true; // Write Header Once
        
        DWORD magic_number  = FILE_HEADER_MAGIC_NUMBER;
        WORD  version_major = FILE_HEADER_VERSION_MAJOR;
        WORD  version_minor = FILE_HEADER_VERSION_MINOR;
        DWORD thiszone      = FILE_HEADER_RESERVED_1;
        DWORD sigfigs       = FILE_HEADER_RESERVED_2;
        DWORD snaplen       = FILE_HEADER_SPAN_LEN;
        DWORD network       = FILE_HEADER_NEIWORKTYPE;
        
        ptr = (typeFrameByte *) &magic_number;
        OutVector.insert(OutVector.end(), ptr, ptr + sizeof(magic_number));
        ptr = (typeFrameByte *) &version_major;
        OutVector.insert(OutVector.end(), ptr, ptr + sizeof(version_major));
        ptr = (typeFrameByte *) &version_minor;
        OutVector.insert(OutVector.end(), ptr, ptr + sizeof(version_minor));
        ptr = (typeFrameByte *) &thiszone;
        OutVector.insert(OutVector.end(), ptr, ptr + sizeof(thiszone));
        ptr = (typeFrameByte *) &sigfigs;
        OutVector.insert(OutVector.end(), ptr, ptr + sizeof(sigfigs));
        ptr = (typeFrameByte *) &snaplen;
        OutVector.insert(OutVector.end(), ptr, ptr + sizeof(snaplen));
        ptr = (typeFrameByte *) &network;
        OutVector.insert(OutVector.end(), ptr, ptr + sizeof(network));
    }

    OutVector.insert(OutVector.end(), frame, frame + len);

    return(OutVector);
}

void 
Output_Frame(typeFrameByte frame[], int len) {
    typeFrameVector OutVector = WireSharkPacket(frame, len);
    DWORD dwWritten;

    WriteFile(hCaptureOutputPipe, OutVector.data(), OutVector.size(), &dwWritten, NULL);
}  

void 
ProcessFrames() {
    DWORD dwWaitResult;
    while(1) {
        dwWaitResult = WaitForSingleObject(hCommFrameReadyEvent, INFINITE); // indefinite wait for event
        typeFrameVector FrameVector=SerialFrameVector;
        ResetEvent(hCommFrameReadyEvent);
        SetEvent(hCommFrameQueuedEvent);

        Output_Frame(FrameVector.data() , FrameVector.size());
    }
}

HANDLE 
CreateNamedPipe(string &pipe_name){
    HANDLE hPipe = INVALID_HANDLE_VALUE; 
    /* create the pipe */
    while (hPipe == INVALID_HANDLE_VALUE) {
        /* use CreateFile rather than CreateNamedPipe */
        hPipe = CreateFileA(pipe_name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (hPipe != INVALID_HANDLE_VALUE) {
            break;
        }
        /* if an error occured at handle creation */
        if (!WaitNamedPipeA(pipe_name.c_str(), 20000)) {
            printf("Could not open pipe: waited for 20sec!\n"
                   "If this message was issued before the 20sec finished,\n"
                   "then the pipe doesn't exist!\n");
            return hPipe;
        }
    }
    ConnectNamedPipe(hPipe, NULL);

    return hPipe;
}

bool 
StringReplace(string &str, const string &from, const string &to) {
    size_t start_pos = str.find(from);
    if(start_pos == string::npos) {
        return false;
    }
    str.replace(start_pos, from.length(), to);
    
    return true;
}

void 
print_extcap_config_comport() {
    string argString = "";
    argString += "arg {number=0}{call=--port}{display=Port}{type=selector}\n";

    /* We iterate through all of them seeing if we can open them or 
       if we fail to open them, get an access denied or general error */
    for (int i = 1; i <= MAX_SERIAL_NUMBER; i++){
        //Form the Raw device name
        char szPort[32];
        char argSubString[256];
        argSubString[0] = TEXT('\0');
        szPort[0]       = TEXT('\0');
        sprintf(szPort, "\\\\.\\COM%u", i);

        //Try to open the port
        HANDLE hCom   = CreateFileA(szPort, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
        DWORD dwError = GetLastError();
        if (hCom != INVALID_HANDLE_VALUE) {
          //The port was opened successfully
          CloseHandle(hCom);
          sprintf(argSubString,"value {arg=0}{value=%u}{display=COM%u}{default=false}\n", i, i);
          argString += argSubString;
        } else {
            //Check to see if the error was because some other app had the port open or a general failure
            if (dwError == ERROR_ACCESS_DENIED     || dwError == ERROR_GEN_FAILURE || 
                dwError == ERROR_SHARING_VIOLATION || dwError == ERROR_SEM_TIMEOUT) {
                sprintf(argSubString,"value {arg=0}{value=%u}{display=COM%u (IN USE)}{default=false}\n", i, i);
                argString += argSubString;
            }
        }
    }
    printf("%s", argString.c_str());
}

void 
print_extcap_config_baud() {
    string  argString = "";
    argString += "arg {number=1}{call=--baud}{display=Baud Rate}{type=selector}\n";
    
    // Check if the file exists
    ifstream file("./baud.ini");
    if (file.is_open()) {
        string line;
        while (getline(file, line)) {
            argString += "value {arg=1}{value=" + line + "}{display=" + line + "}{default=false}\n";
        }
        file.close();
    } else {
        int numOfBaudRates = 16;
        string AvailableBaudRates[numOfBaudRates] = {"1200",   "2400",   "4800",   "9600",   "14400", "19200",  
                                                     "38400",  "56000",  "57600",  "76800",  "115200", 
                                                     "128000", "230400", "256000", "480000", "921600"};  
        for (int baudRate = 0; baudRate < numOfBaudRates; baudRate++) {
            argString += "value {arg=1}{value=" + AvailableBaudRates[baudRate] + "}{display=" + AvailableBaudRates[baudRate] + "}{default=false}\n";
        }
    }
    printf("%s", argString.c_str());
}

void 
print_extcap_config_bytesize() {
    string argString = "";  
    argString += "arg {number=2}{call=--byte}{display=Byte Size}{type=selector}\n";
    argString += "value {arg=2}{value=8}{display=8}{default=true}\n";
    argString += "value {arg=2}{value=7}{display=7}{default=false}\n";
    printf("%s", argString.c_str());
}

void 
print_extcap_config_parity() {
    string argString = "";  
    argString += "arg {number=3}{call=--parity}{display=Parity}{type=selector}\n";
    argString += "value {arg=3}{value=NONE}{display=NONE}{default=true}\n";
    argString += "value {arg=3}{value=ODD}{display=ODD}{default=false}\n";
    argString += "value {arg=3}{value=EVEN}{display=EVEN}{default=false}\n";
    printf("%s", argString.c_str());
}

void 
print_extcap_config_stopbits() {
    string argString = "";  
    argString += "arg {number=4}{call=--stop}{display=Stop Bits}{type=selector}\n";
    argString += "value {arg=4}{value=1}{display=1}{default=true}\n";
    argString += "value {arg=4}{value=2}{display=2}{default=false}\n";
    printf("%s", argString.c_str());
}

void 
print_extcap_config_channel() {
    string argString = "";  
    argString += "arg {number=5}{call=--channel}{display=Channel}{type=selector}\n";

    string nowChannel = Channel;
    for (int channel = 11; channel <= 26; channel++) {
        nowChannel[0] = (BYTE)((channel / 10) + 0x30);
        nowChannel[1] = (BYTE)((channel % 10) + 0x30);
        argString += "value {arg=5}{value=" + nowChannel + "}{display=" + nowChannel + "}{default=true}\n";
    }

    printf("%s", argString.c_str());
}

void 
print_extcap_config() {
    print_extcap_config_comport();
    print_extcap_config_baud();
    print_extcap_config_bytesize();
    print_extcap_config_parity();
    print_extcap_config_stopbits();
    print_extcap_config_channel();
}

void 
print_extcap_interfaces() {
    /* note: format for Wireshark ExtCap */
    string  argString=""; 
    argString += "interface {value=" + WIRESHARK_ADAPTER_NAME + "}{display=" +  WIRESHARK_ADAPTER_NAME +"}\n"; 
    
    //Test GUI Menu Interface
    if(USE_QUI_MENU) {
        argString += "extcap {version=1.0}{display=Example extcap interface}\n"; 
        argString += "control {number=0}{type=string}{display=Message}\n";
        argString += "control {number=1}{type=selector}{display=Time delay}{tooltip=Time delay between packages}\n";
        argString += "control {number=2}{type=boolean}{display=Verify}{default=true}{tooltip=Verify package content}\n";
        argString += "control {number=3}{type=button}{display=Turn on}{tooltip=Turn on or off}\n";
        argString += "control {number=4}{type=button}{role=logger}{display=Log}{tooltip=Show capture log}\n";
        argString += "value {control=1}{value=1}{display=1 sec}\n";
        argString += "value {control=1}{value=2}{display=2 sec}{default=true}\n";
    }
    printf("%s", argString.c_str());
}

void 
print_extcap_dlt(string sInterface) {
    /* note: format for Wireshark ExtCap */
    string argString = "dlt {number=147}{name=" + WIRESHARK_ADAPTER_NAME + "}{display=" +  WIRESHARK_ADAPTER_NAME + "}\n"; 
    printf("%s", argString.c_str());
}

bool 
ParseMainArg(int argc, char *argv[]) {
    int argi                = 0;
    bool Wireshark_Capture  = false;
    bool PrintArgExit       = false;
    string sExtcapInterface = "";
    string sArgMainOpt      = "";

    /* decode any command line parameters */
    for (argi = 1; argi < argc && !PrintArgExit; argi++) {   
        if (strcmp(argv[argi], "--version") == 0) {
            printf("%d", PROGRAMM_VERSION);
            PrintArgExit = true;
        } else
        if (strcmp(argv[argi], "--extcap-interfaces") == 0) {
            print_extcap_interfaces();
            PrintArgExit = true;
        } else 
        if (strcmp(argv[argi], "--extcap-config") == 0) {
            print_extcap_config();
            PrintArgExit = true;
        } else
        if (strcmp(argv[argi], "--extcap-dlts") == 0) {
            sArgMainOpt  = "--extcap-dlts";
            PrintArgExit = true;
        } else
        if (strcmp(argv[argi], "--capture") == 0)  {
            Wireshark_Capture = true;
        }  

        int iCaseIndex = 0;
        string sArgOpt = "";
        string *pArgOptValue;
        bool xExitCaseLoop = false;

        do {
            switch(iCaseIndex) {
            case 0:
                sArgOpt      = "--fifo";
                pArgOptValue = &CaptureOutputPipeName;
                break;
            case 1:
                sArgOpt      = "--extcap-control-in";
                pArgOptValue = &ControlInPipeName;
                break;
            case 2:
                sArgOpt      = "--extcap-control-out";
                pArgOptValue = &ControlOutPipeName;
                break;                                
            case 3:
                sArgOpt      = "--extcap-interface";
                pArgOptValue = &sExtcapInterface;
                break;
            case 4:
                sArgOpt      = "--port";
                pArgOptValue = &Port;
                break;
            case 5:
                sArgOpt      = "--baud";
                pArgOptValue = &BaudRate;
                break;
            case 6:
                sArgOpt      = "--byte";
                pArgOptValue = &ByteSize;
                break;    
            case 7:
                sArgOpt      = "--parity";
                pArgOptValue = &Parity;
                break;    
            case 8:
                sArgOpt      = "--stop";
                pArgOptValue = &StopBits;
                break;         
            case 9:
                sArgOpt      = "--channel";
                pArgOptValue = &Channel;
                break;            
            default:
                xExitCaseLoop = true;
            }

            //Check if second part of ARG is valid
            if  (sArgOpt.compare(argv[argi]) == 0 && !xExitCaseLoop) {
                xExitCaseLoop=true; //Arg Found Exit Case Loop
                argi++;
                if (argi >= argc) {
                    PrintArgExit     = true;  //Arg was not passed correctly Exit routine
                    string argString = "";  
                    argString        = sArgOpt + " requires a value to be provided";
                    
                    printf("%s", argString.c_str());
                } else {
                    *pArgOptValue = argv[argi];
                } 
            }
            iCaseIndex++;
        } while(!xExitCaseLoop);
      //End of For Statement
    }

    if(sArgMainOpt.compare("--extcap-dlts") == 0) {
        if(sExtcapInterface.empty()) {
            string  argString = "";  
            argString = sArgMainOpt + " requires interface to be provided";
            printf("%s", argString.c_str());
        } else {
            print_extcap_dlt(sExtcapInterface);
        }
    }

    return (Wireshark_Capture && !PrintArgExit); 
}

DWORD WINAPI 
ControlInThreadFunc(LPVOID lpParam) {
    OVERLAPPED ovl;
    hControlInEvent=ovl.hEvent=CreateEvent(NULL, TRUE, FALSE, NULL);

    /* create the pipe */
    HANDLE hPipe = INVALID_HANDLE_VALUE; 
    while (hPipe == INVALID_HANDLE_VALUE) {
        /* use CreateFile rather than CreateNamedPipe */
        hPipe = CreateFileA(ControlInPipeName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, 
                            NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
        if (hPipe != INVALID_HANDLE_VALUE) {
            break;
        }
        /* if an error occured at handle creation */
        if (!WaitNamedPipeA(ControlInPipeName.c_str(), 20000)) {
            printf("Could not open pipe: waited for 20sec!\n"
                   "If this message was issued before the 20sec finished,\n"
                   "then the pipe doesn't exist!\n");
            return 0;
        }
    }
    ConnectNamedPipe(hPipe, NULL);

    typeFrameVector FrameVector;
    typeFrameByte RX_CHAR[UART_BUFFER_SIZE];
    DWORD RX_LEN = 0;

    char SyncPipeChar;
    WORD wMessageLength = 0;
    BYTE ControlNumber;
    BYTE Command;

    while(1) {
        BOOL SeccessfullyReadin = ::ReadFile(hPipe, &RX_CHAR, sizeof(RX_CHAR), (LPDWORD)((void *)&RX_LEN), &ovl);
        if(!SeccessfullyReadin){
            DWORD err = ::GetLastError();
            if(err == ERROR_IO_PENDING) {
                SeccessfullyReadin = ::GetOverlappedResult(hPipe, &ovl, &RX_LEN, TRUE);
                if(!SeccessfullyReadin) {
                    DWORD err = ::GetLastError();
                    continue;
                }
            } else {
                continue;
            }
        }

        if(RX_LEN > 0) {
            FrameVector.insert(FrameVector.end(), RX_CHAR, RX_CHAR+RX_LEN);
        }

        if(FrameVector.size() >= 6) {
            SyncPipeChar = FrameVector.data()[0];
            
            int x = 1;
            if(*(char*)&x == 1) { //Little Ended Swap Bytes for network order
                wMessageLength = (FrameVector.data()[3]) | ((FrameVector.data()[2] & 0xff) << 8);
            } else {
                wMessageLength = (FrameVector.data()[2]) | ((FrameVector.data()[3] & 0xff) << 8);
            }

            ControlNumber = FrameVector.data()[4];
            Command       = FrameVector.data()[5];


            if(FrameVector.size() >= wMessageLength + 4) {
                string sPayload((const char*)&(FrameVector.data()[6]), wMessageLength - 2);;
                string sOutput = "";
                sOutput += "SyncPipeChar: "     + to_string(SyncPipeChar);
                sOutput += " wMessageLength: "  + to_string(wMessageLength);
                sOutput += " ControlNumber: "   + to_string(ControlNumber);
                sOutput += " FrameVectorSize: " + to_string(FrameVector.size());
                sOutput += " Command: "         + to_string(Command);
                sOutput += "\nPayload: "        + sPayload + "\n\n";            
                FrameVector.clear();
            }
        } 
    }
}


int 
CreateControlInThread(void) {
    int RetStatus = 0;
    
    hControlInThread = CreateThread(NULL, 0, ControlInThreadFunc, NULL, 0, NULL);
    if (hControlInThread == INVALID_HANDLE_VALUE || hControlInThread == NULL) {
        cout << "Creating Thread Error";
        CloseHandle(hControlInThread);
    } else {
        RetStatus = 1;
    }

    return(RetStatus);
}

void 
on_main_exit(void) {
    CloseHandle(hComSerial);
    CloseHandle(hCommReadThread);
    CloseHandle(hCommFrameReadyEvent);
    CloseHandle(hCommFrameQueuedEvent);
    CloseHandle(hCaptureOutputPipe);
    CloseHandle(hControlOutPipe);
    CloseHandle(hControlInThread);
    CloseHandle(hControlInEvent);  
    CloseHandle(hControlInPipe); 
}

uint64_t 
SetMinimumTimerResolution() {
    static NTSTATUS(__stdcall *NtQueryTimerResolution)(OUT PULONG MinimumResolution, OUT PULONG MaximumResolution, OUT PULONG ActualResolution) = (NTSTATUS(__stdcall*)(PULONG, PULONG, PULONG))GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryTimerResolution");
    static NTSTATUS(__stdcall *NtSetTimerResolution)(IN ULONG RequestedResolution, IN BOOLEAN Set, OUT PULONG ActualResolution) = (NTSTATUS(__stdcall*)(ULONG, BOOLEAN, PULONG))GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetTimerResolution");

    if ((NtQueryTimerResolution == nullptr) || (NtSetTimerResolution == nullptr)) {
        return 0;
    }

    ULONG MinimumResolution, MaximumResolution, ActualResolution;

    NTSTATUS ns = NtQueryTimerResolution(&MinimumResolution, &MaximumResolution, &ActualResolution);
    if (ns == 0) {
        ns = NtSetTimerResolution(min(MinimumResolution, MaximumResolution), TRUE, &ActualResolution);
        if (ns == 0) {
            return (ActualResolution * 100);
        }
    }

    return 1000000;
} 

int 
main(int argc, char *argv[]) {
    SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), ENABLE_PROCESSED_INPUT);
    
    ULONG currentRes;
    if (ParseMainArg(argc, argv) == 0) {
        return(0);
    } else {
        atexit(on_main_exit);
        SetMinimumTimerResolution();
        hCaptureOutputPipe = CreateNamedPipe(CaptureOutputPipeName);
        CreateControlInThread();
        hControlOutPipe = CreateNamedPipe(ControlOutPipeName);
        CreateComThread();
        ProcessFrames();
    }

    return 0;
}
