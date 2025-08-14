/*
Wireshark Serial Adapter
Copyright (C) 2025 Joel Z.

This software is licensed under the terms of the GNU General Public License
as published by the Free Software Foundation, either version 3 of the License,
or (at your option) any later version.

This means:

- You may use, study, modify, and redistribute this software freely.
- However, **any modified versions must also be released under the GPL license**.
- **Any use of this software or its modified versions must remain open, free,
  and publicly accessible.**
- You must clearly indicate any changes made and publish source code accordingly.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <iostream>
#include <windows.h>
#include <unistd.h>
#include <math.h> //USED FOR CEIL
#include <vector>
#include <queue>
#include <chrono> //Used for System Time
#include <fstream> //USED for File Handling
#include <stdio.h>

using namespace std;

const double ProgramVersion=2.0;
const std::string WireSharkAdapterName="Zigbee Sniffer";
const boolean GuiMenu=true;
std::string FileName="";
std::string Port="5";
std::string BaudRate="921600";
std::string ByteSize="8";
std::string StopBits="1";
std::string Parity="NONE";
std::string FrameTiming="event";
std::string Channel="11";
std::string FrameDelay="15";
std::string CaptureOutputPipeName="";
std::string ControlInPipeName="";
std::string ControlOutPipeName="";

static HANDLE hComSerial = INVALID_HANDLE_VALUE;
static HANDLE hCommReadThread = INVALID_HANDLE_VALUE;
static HANDLE hCommFrameReadyEvent = INVALID_HANDLE_VALUE;
static HANDLE hCommFrameQueuedEvent= INVALID_HANDLE_VALUE;
static HANDLE hCaptureOutputPipe = INVALID_HANDLE_VALUE;     /* pipe handle */
static HANDLE hControlInPipe = INVALID_HANDLE_VALUE;     /* pipe handle */
static HANDLE hControlInThread = INVALID_HANDLE_VALUE;    
static HANDLE hControlInEvent = INVALID_HANDLE_VALUE;    
static HANDLE hControlOutPipe = INVALID_HANDLE_VALUE;     /* pipe handle */

typedef unsigned char typeFrameByte;
typedef std::vector<typeFrameByte> typeFrameVector;
typedef std::queue< typeFrameVector > typeFrameQueue;
typeFrameQueue  InputQueue;
std::vector<std::string> ComPortStringVector;
typeFrameVector FragmentVector;
typeFrameVector SerialFrameVector;

DWORD WINAPI ComReadThreadFunc(LPVOID lpParam) 
{
    std::string mPORT ("\\\\.\\COM" + Port);
    DWORD       mBaudRate=std::stoi(BaudRate);
    BYTE        mByteSize=std::stoi(ByteSize);
    BYTE        mStopBits=ONESTOPBIT;
    if (StopBits.compare("2")==0) mStopBits=TWOSTOPBITS;
    BYTE        mParity=NOPARITY;
    if (Parity.compare("NONE")==0) mParity=NOPARITY;
    if (Parity.compare("ODD")==0)  mParity=ODDPARITY;
    if (Parity.compare("EVEN")==0) mParity=EVENPARITY;

    hComSerial = CreateFileA( mPORT.c_str(), // TEXT("\\\\.\\COM3"),
    GENERIC_READ | GENERIC_WRITE,
    FILE_SHARE_READ|FILE_SHARE_WRITE, // 0,    // exclusive access
    NULL, // default security attributes
    OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL, //FILE_ATTRIBUTE_NORMAL //FILE_FLAG_OVERLAPPED
    NULL
    );

    // Do some basic settings
    BOOL fSuccess;
    DCB serialParams = { 0 };
    serialParams.DCBlength = sizeof(DCB);
    fSuccess=GetCommState(hComSerial, &serialParams);

    serialParams.BaudRate = mBaudRate; //CBR_115200;
    serialParams.ByteSize = mByteSize; //8;
    serialParams.Parity = mParity; //EVENPARITY;
    serialParams.StopBits = mStopBits; //ONESTOPBIT;
    serialParams.fOutxCtsFlow=false;
    serialParams.fOutxDsrFlow=false;
    serialParams.fDtrControl=0;
    serialParams.fDsrSensitivity=false;
    serialParams.fTXContinueOnXoff=false;
    serialParams.fOutX=false;
    serialParams.fInX=false;
    serialParams.fNull=false;
    serialParams.fRtsControl=0;

    fSuccess=SetCommState(hComSerial, &serialParams);
    GetCommState(hComSerial, &serialParams);

    double ReadTimeOut=std::stod(FrameDelay);

    // Set timeouts 
    COMMTIMEOUTS timeout = { 0 };
    if(strcmp(FrameTiming.c_str(), "polling") == 0)
    {
        // ReadIntervalTimeout with a value of MAXDWORD, combined with zero values for both the 
        // ReadTotalTimeoutConstant and ReadTotalTimeoutMultiplier members, specifies 
        // that the read operation is to return immediately with the bytes that 
        // have already been received, even if no bytes have been received.  
        timeout.ReadIntervalTimeout = MAXDWORD;
        timeout.ReadTotalTimeoutMultiplier = 0;
        timeout.ReadTotalTimeoutConstant =  0; 
    }
    else
    {
        //One of the following below occurs when the ReadFile function is called if an application sets 
        // ReadIntervalTimeout=MAXDWORD;
        // ReadTotalTimeoutMultiplier=MAXDWORD; 
        // MAXDWORD > ReadTotalTimeoutConstant > 0 

        // *If there are any bytes in the input buffer, ReadFile returns immediately with the bytes in the buffer.
        // *If there are no bytes in the input buffer, ReadFile waits until a byte arrives and then returns immediately.
        // *If no bytes arrive within the time specified by ReadTotalTimeoutConstant, ReadFile times out.
        timeout.ReadIntervalTimeout = MAXDWORD; 
        timeout.ReadTotalTimeoutMultiplier = MAXDWORD;
        timeout.ReadTotalTimeoutConstant =  1; //Fixed 1ms Timeout
    }
    timeout.WriteTotalTimeoutMultiplier = 0;
    timeout.WriteTotalTimeoutConstant = 0;
    SetCommTimeouts(hComSerial, &timeout);

    typeFrameByte RX_CHAR[1024];
    int RX_LEN;
    DWORD dwCommEvent;

    if (!SetCommMask(hComSerial, EV_RXCHAR));   // Error setting communications event mask.
    PurgeComm(hComSerial, PURGE_RXCLEAR|PURGE_TXCLEAR);
    ReadFile(hComSerial, &RX_CHAR, 1023, (LPDWORD)((void *)&RX_LEN), NULL);
    
    bool b;
    double EV_Timeout=0;
    LARGE_INTEGER freq, start, end;

    typeFrameByte SetChannelCommand[2] = {0xCA, (BYTE)((Channel[0] - 0x30) * 10 + (Channel[1] - 0x30))};
    WriteFile(hComSerial, &SetChannelCommand, 2, NULL, NULL);

    while(hComSerial !=INVALID_HANDLE_VALUE)
    {
        if (WaitCommEvent(hComSerial, &dwCommEvent, NULL))
        { 
            do
            {
                RX_LEN=0;
                b=ReadFile(hComSerial, &RX_CHAR, 1023, (LPDWORD)((void *)&RX_LEN), NULL);
                if (RX_LEN>0 && b)
                {
                    // A Data has been read; process it.
                    SerialFrameVector.insert(SerialFrameVector.end(), RX_CHAR, RX_CHAR+RX_LEN);
                    QueryPerformanceCounter(&start);
                    EV_Timeout = 0;
                }
                else
                {
                    if(timeout.WriteTotalTimeoutConstant==0) 
                    {
                        usleep(static_cast<useconds_t>(ReadTimeOut/2)); //Wait half the readtimeout to free CPU resource and wait for more data to be recieved
                        QueryPerformanceFrequency(&freq);
                        QueryPerformanceCounter(&end);
                        // subtract before dividing to improve precision
                        EV_Timeout = static_cast<double>(end.QuadPart - start.QuadPart) / static_cast<double>(freq.QuadPart/1000000);
                    }
                    else
                    {
                        EV_Timeout = EV_Timeout + 1000;  //Using fixed time of 1ms for ReadFile timeout
                    }
                }
            } 
            while(EV_Timeout<ReadTimeOut);
            
            if(!SerialFrameVector.empty())
            {                
                SetEvent(hCommFrameReadyEvent); //Send Frame to be buffered to Queue
                WaitForSingleObject(hCommFrameQueuedEvent, INFINITE);    // indefinite wait for event frame Queue Event 
                ResetEvent(hCommFrameQueuedEvent);
                SerialFrameVector.clear();
            }
        }
    }
    return 0;
}

int CreateComThread()
{
    int RetValue=0;

    hCommReadThread = CreateThread(NULL, 0, ComReadThreadFunc, NULL, 0, NULL);

    hCommFrameQueuedEvent = CreateEvent( 
    NULL,               // default security attributes
    TRUE,               // manual-reset event
    FALSE,              // initial state is nonsignaled
    TEXT("FrameQueuedEvent")  // object name
    ); 

    hCommFrameReadyEvent = CreateEvent( 
    NULL,               // default security attributes
    TRUE,               // manual-reset event
    FALSE,              // initial state is nonsignaled
    TEXT("CommFrameReadyEvent")  // object name
    ); 

    if (    hCommReadThread == INVALID_HANDLE_VALUE || 
            hCommFrameReadyEvent == INVALID_HANDLE_VALUE || 
            hCommReadThread==NULL || 
            hCommFrameReadyEvent==NULL ||
            hCommFrameQueuedEvent==NULL || 
            hCommFrameQueuedEvent==NULL)
    {
        cout<<"Creating Thread Error";
        CloseHandle(hCommReadThread);
        CloseHandle(hCommFrameReadyEvent);
        CloseHandle(hCommFrameQueuedEvent);
    }
    else
    {
        RetValue=1;
    }

    return(RetValue);
}

typeFrameVector WireSharkPacket(typeFrameByte  frame[], int len)
{
    static bool xHeaderWritten=false;
    typeFrameVector OutVector;
    typeFrameByte *ptr;

    if (!xHeaderWritten)
    {
        xHeaderWritten=true; //Write Header Once
        

        DWORD magic_number = 0xA1B2C3D4; /* magic number */
        WORD version_major = 0x0002;     /* major version number */
        WORD version_minor = 0x0004;     /* minor version number */
        DWORD thiszone     = 0x00000000; /* GMT to local correction */
        DWORD sigfigs      = 0x00000000; /* accuracy of timestamps */
        DWORD snaplen      = 0x00040000; /* max length of captured packets, in octets */
        DWORD network      = 0x0000011B;
        

        ptr=(typeFrameByte *) &magic_number;
        OutVector.insert(OutVector.end(), ptr, ptr + sizeof(magic_number));
        ptr=(typeFrameByte *) &version_major;
        OutVector.insert(OutVector.end(), ptr, ptr + sizeof(version_major));
        ptr=(typeFrameByte *) &version_minor;
        OutVector.insert(OutVector.end(), ptr, ptr + sizeof(version_minor));
        ptr=(typeFrameByte *) &thiszone;
        OutVector.insert(OutVector.end(), ptr, ptr + sizeof(thiszone));
        ptr=(typeFrameByte *) &sigfigs;
        OutVector.insert(OutVector.end(), ptr, ptr + sizeof(sigfigs));
        ptr=(typeFrameByte *) &snaplen;
        OutVector.insert(OutVector.end(), ptr, ptr + sizeof(snaplen));
        ptr=(typeFrameByte *) &network;
        OutVector.insert(OutVector.end(), ptr, ptr + sizeof(network));
    }

    OutVector.insert(OutVector.end(), frame, frame+len);

    return(OutVector);
}

void Output_Frame(typeFrameByte frame[], int len)
{
    //print_hex(frame, len);
    //cout<<" I: "<<InputQueue.size();

    typeFrameVector OutVector = WireSharkPacket(frame, len);
    //DEBUG
    //print_hex(OutVector.data() , OutVector.size());
    //cout<<endl<<endl;
    DWORD dwWritten;
    WriteFile(hCaptureOutputPipe, OutVector.data(), OutVector.size(), &dwWritten, NULL);

}  

void ProcessFrames()
{
     while(1)
     {
         DWORD dwWaitResult;
        dwWaitResult = WaitForSingleObject(hCommFrameReadyEvent, INFINITE);    // indefinite wait for event
        typeFrameVector FrameVector=SerialFrameVector;
        ResetEvent(hCommFrameReadyEvent);
        SetEvent(hCommFrameQueuedEvent);

        Output_Frame(FrameVector.data() , FrameVector.size());
    }
}

char *filename_remove_path(const char *filename_in)
{
    char *filename_out = (char *) filename_in;

    /* allow the device ID to be set */
    if (filename_in) {
        filename_out = strrchr(filename_in, '\\');
        if (!filename_out) {
            filename_out = strrchr(filename_in, '/');
        }
        /* go beyond the slash */
        if (filename_out) {
            filename_out++;
        } else {
            /* no slash in filename */
            filename_out = (char *) filename_in;
        }
    }

    return filename_out;
}



HANDLE CreateNamedPipe(std::string& pipe_name)
{
    HANDLE hPipe = INVALID_HANDLE_VALUE; 
    /* create the pipe */
    while (hPipe == INVALID_HANDLE_VALUE)
    {
        /* use CreateFile rather than CreateNamedPipe */
        hPipe = CreateFileA(
            pipe_name.c_str(),
            GENERIC_READ |
            GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL);
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

bool StringReplace(std::string& str, const std::string& from, const std::string& to) {
    size_t start_pos = str.find(from);
    if(start_pos == std::string::npos)
        return false;
    str.replace(start_pos, from.length(), to);
    return true;
}

void print_extcap_config_comport()
{
    std::string  argString="";

    argString+="arg {number=0}{call=--port}{display=Port}{type=selector}\n";

    //Up to 255 COM ports are supported so we iterate through all of them seeing
    //if we can open them or if we fail to open them, get an access denied or general error error.
    //Both of these cases indicate that there is a COM port at that number.
    for (int i=1; i<256; i++)
        {
        //Form the Raw device name
        char szPort[32];
        char argSubString[256];
        argSubString[0] = TEXT('\0');
        szPort[0] = TEXT('\0');
        sprintf (szPort, "\\\\.\\COM%u", i);

        //Try to open the port
        HANDLE hCom=CreateFileA(szPort, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
        DWORD dwError = GetLastError();
        if (hCom != INVALID_HANDLE_VALUE)
        {
          //The port was opened successfully
          CloseHandle(hCom);
          sprintf(argSubString,"value {arg=0}{value=%u}{display=COM%u}{default=false}\n",i,i);
          argString+=argSubString;
        }
        else
        {
            //Check to see if the error was because some other app had the port open or a general failure
            if (dwError == ERROR_ACCESS_DENIED || dwError == ERROR_GEN_FAILURE || dwError == ERROR_SHARING_VIOLATION || dwError == ERROR_SEM_TIMEOUT)
            {
                sprintf(argSubString,"value {arg=0}{value=%u}{display=COM%u (IN USE)}{default=false}\n",i,i);
                argString+=argSubString;
            }
        }
    }
    printf("%s", argString.c_str());
}

void print_extcap_config_baud()
{
    std::string  argString="";
    argString+="arg {number=1}{call=--baud}{display=Baud Rate}{type=selector}\n";
    // Check if the file exists
    ifstream file("./baud.ini");
    if (file.is_open()) {
        // Read the file line by line
        string line;
        while (getline(file, line)) 
        {
            argString+="value {arg=1}{value=" + line + "}{display=" + line + "}{default=false}\n";
        }
        // Close the file
        file.close();
    }
    else
    {
        argString+="value {arg=1}{value=1200}{display=1200}{default=false}\n";
        argString+="value {arg=1}{value=2400}{display=2400}{default=false}\n";
        argString+="value {arg=1}{value=4800}{display=4800}{default=false}\n";
        argString+="value {arg=1}{value=9600}{display=9600}{default=false}\n";
        argString+="value {arg=1}{value=14400}{display=14400}{default=false}\n";
        argString+="value {arg=1}{value=19200}{display=19200}{default=true}\n";
        argString+="value {arg=1}{value=38400}{display=38400}{default=false}\n";
        argString+="value {arg=1}{value=56000}{display=56000}{default=false}\n";
        argString+="value {arg=1}{value=57600}{display=57600}{default=false}\n";
        argString+="value {arg=1}{value=76800}{display=76800}{default=false}\n";
        argString+="value {arg=1}{value=115200}{display=115200}{default=false}\n";
        argString+="value {arg=1}{value=128000}{display=128000}{default=false}\n";
        argString+="value {arg=1}{value=230400}{display=230400}{default=false}\n";
        argString+="value {arg=1}{value=256000}{display=256000}{default=false}\n";
        argString+="value {arg=1}{value=480000}{display=480000}{default=false}\n";
        argString+="value {arg=1}{value=921600}{display=921600}{default=false}\n";
    }
     printf("%s", argString.c_str());
}

void print_extcap_config_bytesize()
{
    std::string  argString="";  
    argString+="arg {number=2}{call=--byte}{display=Byte Size}{type=selector}\n";
    argString+="value {arg=2}{value=8}{display=8}{default=true}\n";
    argString+="value {arg=2}{value=7}{display=7}{default=false}\n";
    printf("%s", argString.c_str());
}

void print_extcap_config_parity()
{
    std::string  argString="";  
    argString+="arg {number=3}{call=--parity}{display=Parity}{type=selector}\n";
    argString+="value {arg=3}{value=NONE}{display=NONE}{default=true}\n";
    argString+="value {arg=3}{value=ODD}{display=ODD}{default=false}\n";
    argString+="value {arg=3}{value=EVEN}{display=EVEN}{default=false}\n";
    printf("%s", argString.c_str());
}

void print_extcap_config_stopbits()
{
    std::string  argString="";  
    argString+="arg {number=4}{call=--stop}{display=Stop Bits}{type=selector}\n";
    argString+="value {arg=4}{value=1}{display=1}{default=true}\n";
    argString+="value {arg=4}{value=2}{display=2}{default=false}\n";
    printf("%s", argString.c_str());
}

void print_extcap_config_channel()
{
    std::string  argString="";  
    argString+="arg {number=5}{call=--channel}{display=Channel}{type=selector}\n";
    argString+="value {arg=5}{value=11}{display=11}{default=true}\n";
    argString+="value {arg=5}{value=12}{display=12}{default=false}\n";
    argString+="value {arg=5}{value=13}{display=13}{default=false}\n";
    argString+="value {arg=5}{value=14}{display=14}{default=false}\n";
    argString+="value {arg=5}{value=15}{display=15}{default=false}\n";
    argString+="value {arg=5}{value=16}{display=16}{default=false}\n";
    argString+="value {arg=5}{value=17}{display=17}{default=false}\n";
    argString+="value {arg=5}{value=18}{display=18}{default=false}\n";
    argString+="value {arg=5}{value=19}{display=19}{default=false}\n";
    argString+="value {arg=5}{value=20}{display=20}{default=false}\n";
    argString+="value {arg=5}{value=21}{display=21}{default=false}\n";
    argString+="value {arg=5}{value=22}{display=22}{default=false}\n";
    argString+="value {arg=5}{value=23}{display=23}{default=false}\n";
    argString+="value {arg=5}{value=24}{display=24}{default=false}\n";
    argString+="value {arg=5}{value=25}{display=25}{default=false}\n";
    argString+="value {arg=5}{value=26}{display=26}{default=false}\n";
    printf("%s", argString.c_str());
}

void print_extcap_config()
{
    print_extcap_config_comport();
    print_extcap_config_baud();
    print_extcap_config_bytesize();
    print_extcap_config_parity();
    print_extcap_config_stopbits();
    print_extcap_config_channel();
    // print_extcap_config_interframe();
    // print_extcap_config_dlt();
}

void print_extcap_interfaces()
{
     /* note: format for Wireshark ExtCap */
    std::string  argString=""; 
    argString+="interface {value=" + WireSharkAdapterName + "}{display=" +  WireSharkAdapterName +"}\n"; 
    
    //Test GUI Menu Interface
    if(GuiMenu)
    {
        argString+="extcap {version=1.0}{display=Example extcap interface}\n"; 
        argString+="control {number=0}{type=string}{display=Message}\n";
        argString+="control {number=1}{type=selector}{display=Time delay}{tooltip=Time delay between packages}\n";
        argString+="control {number=2}{type=boolean}{display=Verify}{default=true}{tooltip=Verify package content}\n";
        argString+="control {number=3}{type=button}{display=Turn on}{tooltip=Turn on or off}\n";
        argString+="control {number=4}{type=button}{role=logger}{display=Log}{tooltip=Show capture log}\n";
        argString+="value {control=1}{value=1}{display=1 sec}\n";
        argString+="value {control=1}{value=2}{display=2 sec}{default=true}\n";
    }
    printf("%s", argString.c_str());
}

void print_extcap_dlt(std::string sInterface)
{
     /* note: format for Wireshark ExtCap */
    std::string  argString="dlt {number=147}{name=" + WireSharkAdapterName +"_"+ FileName + "}{display=" +  WireSharkAdapterName + " ("+ FileName +")}\n"; 
    printf("%s", argString.c_str());
}

bool ParseMainArg(int argc, char *argv[])
{
     int argi = 0;
    bool Wireshark_Capture=false;
    bool PrintArgExit=false;
    std::string sExtcapInterface="";
    std::string sArgMainOpt="";

     /* decode any command line parameters */
    FileName = filename_remove_path(argv[0]);

    for (argi = 1; argi < argc && !PrintArgExit; argi++) 
    {   
        if (strcmp(argv[argi], "--version") == 0) {printf("%d", ProgramVersion);PrintArgExit=true;} 
        if (strcmp(argv[argi], "--extcap-interfaces") == 0) {print_extcap_interfaces();PrintArgExit=true;} 
        if (strcmp(argv[argi], "--extcap-config") == 0) {print_extcap_config();PrintArgExit=true;}
        if (strcmp(argv[argi], "--extcap-dlts") == 0) {sArgMainOpt="--extcap-dlts";PrintArgExit=true;}  //Special Case--extcap-interface is required
        if (strcmp(argv[argi], "--capture") == 0)  {Wireshark_Capture = true; } //When parameter is used it will Start capature!  

        int iCaseIndex=0;
        std::string sArgOpt="";
        std::string *pArgOptValue;
        bool xExitCaseLoop=false;

        do {
            switch(iCaseIndex) 
            {
            case 0:
                sArgOpt="--fifo";
                pArgOptValue=&CaptureOutputPipeName;
                break;
            case 1:
                sArgOpt="--extcap-control-in";
                pArgOptValue=&ControlInPipeName;
                break;
            case 2:
                sArgOpt="--extcap-control-out";
                pArgOptValue=&ControlOutPipeName;
                break;                                
            case 3:
                sArgOpt="--extcap-interface";
                pArgOptValue=&sExtcapInterface;
                break;
            case 4:
                sArgOpt="--port";
                pArgOptValue=&Port;
                break;
            case 5:
                sArgOpt="--baud";
                pArgOptValue=&BaudRate;
                break;
            case 6:
                sArgOpt="--byte";
                pArgOptValue=&ByteSize;
                break;    
            case 7:
                sArgOpt="--parity";
                pArgOptValue=&Parity;
                break;    
            case 8:
                sArgOpt="--stop";
                pArgOptValue=&StopBits;
                break;   
            case 9:
                sArgOpt="--frame_timing";
                pArgOptValue=&FrameTiming;
                break;       
            case 10:
                sArgOpt="--channel";
                pArgOptValue=&Channel;
                break;            
            default:
                xExitCaseLoop=true;
            }

            //Check if second part of ARG is valid
            if  (sArgOpt.compare(argv[argi]) == 0 && !xExitCaseLoop) 
            {
                xExitCaseLoop=true; //Arg Found Exit Case Loop
                argi++;
                if (argi >= argc) 
                {
                    PrintArgExit=true;  //Arg was not passed correctly Exit routine
                    std::string  argString="";  
                    argString=sArgOpt + " requires a value to be provided";
                    printf("%s", argString.c_str());
                }
                else
                {
                    *pArgOptValue=argv[argi];
                } 
            }
            iCaseIndex++;
        }
        while (!xExitCaseLoop);
      //End of For Statement
    }

    if(sArgMainOpt.compare("--extcap-dlts")==0)  //Special Case--extcap-interface is required
    {
        if(sExtcapInterface.empty())
        {
            std::string  argString="";  
            argString=sArgMainOpt + " requires interface to be provided";
            printf("%s", argString.c_str());
        }
        else
            print_extcap_dlt(sExtcapInterface);
    }

    return (Wireshark_Capture && !PrintArgExit); 
}



DWORD WINAPI ControlInThreadFunc(LPVOID lpParam)
{

    OVERLAPPED ovl;
    hControlInEvent=ovl.hEvent=CreateEvent(NULL, TRUE, FALSE, NULL);

     HANDLE hPipe = INVALID_HANDLE_VALUE; 
    /* create the pipe */
    while (hPipe == INVALID_HANDLE_VALUE)
    {
        /* use CreateFile rather than CreateNamedPipe */
        hPipe = CreateFileA(
            ControlInPipeName.c_str(),
            GENERIC_READ |
            GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
            NULL);
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
    typeFrameByte RX_CHAR[1024];
    DWORD RX_LEN=0;

    char SyncPipeChar;
    WORD wMessageLength=0;
    BYTE ControlNumber;
    BYTE Command;

    while(1)
    { /* read loop */
        BOOL b = ::ReadFile(hPipe, &RX_CHAR, sizeof(RX_CHAR), (LPDWORD)((void *)&RX_LEN), &ovl);
        if(!b)
        { /* failed */
            DWORD err = ::GetLastError();
            if(err == ERROR_IO_PENDING)
                { /* pending */
                b = ::GetOverlappedResult(hPipe, &ovl, &RX_LEN, TRUE);
                if(!b)
                    { /* wait failed */
                    DWORD err = ::GetLastError();
                    //  wnd->PostMessage(UWM_REPORT_ERROR, (WPARAM)err);
                    //  running = FALSE;
                    continue;
                    } /* wait failed */
                } /* pending */
            else
            { /* some other error */
                //wnd->PostMessage(UWM_REPORT_ERROR, (WPARAM)err);
                // running = FALSE;
                continue;
            } /* some other error */
        } /* failed */

        if(RX_LEN > 0)
        { /* has data */
            // wnd->PostMessage(UWM_HAVE_DATA, (WPARAM)bytesRead, (LPARAM)buffer);
            FrameVector.insert(FrameVector.end(), RX_CHAR, RX_CHAR+RX_LEN);
        } /* has data */


        if(FrameVector.size()>=6) 
        {
            SyncPipeChar=FrameVector.data()[0];
            int x = 1;
            if(*(char*)&x==1) //Little Ended Swap Bytes for network order
                wMessageLength=(FrameVector.data()[3])|((FrameVector.data()[2]&0xff)<<8);
            else
                wMessageLength=(FrameVector.data()[2])|((FrameVector.data()[3]&0xff)<<8);
            ControlNumber=FrameVector.data()[4];
            Command=FrameVector.data()[5];


            if(FrameVector.size()>= wMessageLength+4)
            {
                std::string sPayload((const char*)&(FrameVector.data()[6]), wMessageLength-2);;
                string sOutput="";
                sOutput+= "SyncPipeChar: " +  to_string(SyncPipeChar);
                sOutput+=" wMessageLength: " + to_string(wMessageLength);
                sOutput+=" ControlNumber: " + to_string(ControlNumber);
                sOutput+=" FrameVectorSize: " + to_string(FrameVector.size());
                sOutput+=" Command: "+ to_string(Command);
                sOutput+="\nPayload: "+ sPayload +"\n\n";            
                FrameVector.clear();
            }
        } 
    } /* read loop */

}


int CreateControlInThread(void)
{
    int RetValue=0;
    hControlInThread = CreateThread(NULL, 0, ControlInThreadFunc, NULL, 0, NULL);
    if (hControlInThread == INVALID_HANDLE_VALUE || hControlInThread==NULL)
    {
        cout<<"Creating Thread Error";
        CloseHandle(hControlInThread);
    }
    else
    {
        RetValue=1;
    }
    return(RetValue);
}

void on_main_exit(void )
{
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

uint64_t SetMinimumTimerResolution()
{
    static NTSTATUS(__stdcall *NtQueryTimerResolution)(OUT PULONG MinimumResolution, OUT PULONG MaximumResolution, OUT PULONG ActualResolution) = (NTSTATUS(__stdcall*)(PULONG, PULONG, PULONG))GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryTimerResolution");
    static NTSTATUS(__stdcall *NtSetTimerResolution)(IN ULONG RequestedResolution, IN BOOLEAN Set, OUT PULONG ActualResolution) = (NTSTATUS(__stdcall*)(ULONG, BOOLEAN, PULONG))GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetTimerResolution");

    if ((NtQueryTimerResolution == nullptr) || (NtSetTimerResolution == nullptr))
        return 0;

    ULONG MinimumResolution, MaximumResolution, ActualResolution;
    NTSTATUS ns = NtQueryTimerResolution(&MinimumResolution, &MaximumResolution, &ActualResolution);
    if (ns == 0)
    {
        ns = NtSetTimerResolution(std::min(MinimumResolution, MaximumResolution), TRUE, &ActualResolution);
        if (ns == 0)
            return (ActualResolution * 100);
    }
    return 1000000;
} 

int main(int argc, char *argv[])
{
   //
    SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), ENABLE_PROCESSED_INPUT);
    
    ULONG currentRes;
    if (ParseMainArg(argc, argv)==0) 
    {
        return(0);
    }
    else
    {
        atexit(on_main_exit);
        SetMinimumTimerResolution();
        hCaptureOutputPipe=CreateNamedPipe(CaptureOutputPipeName);
        CreateControlInThread();
        hControlOutPipe=CreateNamedPipe(ControlOutPipeName);
        CreateComThread();
        ProcessFrames();
    }

    return 0;
}
