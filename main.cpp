#include <windows.h>
#include <tchar.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <algorithm>

#define STACK_START 0x00007FF000000000

void GetAddressOfData(DWORD pid, const char *data, size_t len,std::vector<char*>& adresses)
{
    static bool first = true;

    std::vector<char*> temp;
    if(first == false)
        temp.reserve(adresses.size());

    HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION , FALSE, pid);
    if(process)
    {
        printf("Entered process\n");
        SYSTEM_INFO si;
        GetSystemInfo(&si);

        MEMORY_BASIC_INFORMATION info;
        std::vector<char> chunk;
        char* p = (char*)STACK_START;
        
        while(p < si.lpMaximumApplicationAddress)
        {
            if(!VirtualQueryEx(process, p, &info, sizeof(info)))
            {
                printf("Virtual query fail\n");
                p += info.RegionSize;
                continue;
            }

            if(info.State != MEM_COMMIT)
            {
                printf("Skipped page(invalid acces)\n");
                p += info.RegionSize;
                continue;
            }

            p = (char*)info.BaseAddress;
            chunk.resize(info.RegionSize);

            SIZE_T bytesRead;
            if(!ReadProcessMemory(process, p, &chunk[0], chunk.size(), &bytesRead))
            {
                printf("Read fail\n");
                p += info.RegionSize;
                continue;
            }

            //Reading over page
            for(size_t i = 0; i < (bytesRead - len); ++i)
            {
                if(memcmp(data,  &chunk[i], len) == 0)
                {    
                    char* adr = (char*)p + i;
                    if(first == true && adresses.size() < adresses.max_size())
                    {
                        adresses.push_back(adr);
                    }
                    else if(temp.size() < temp.max_size())
                    {
                        temp.push_back(adr);
                    }
                }
            }
            p += info.RegionSize;
        }
    }
    if(first == false){
        printf("Intersecting adresses...\n");

        std::vector<char*> intersection;
        intersection.resize(min( adresses.size(),temp.size() ));

        std::set_intersection(adresses.begin(),adresses.end(),
                            temp.begin(),temp.end(),
                            intersection.begin());
                            
        intersection.erase(std::remove(intersection.begin(),intersection.end(),nullptr),intersection.end());

        adresses = std::move(intersection);
    }
    
    if(first == true) 
        first = false;
    CloseHandle(process);
}

void CheckAddressesOfData(DWORD pid, const char *data, size_t len,std::vector<char*>& adresses)
{
    std::vector<char*> temp;
    temp.reserve(adresses.size());

    HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION , FALSE, pid);
    if(process)
    {
        printf("Entered process\n");
        SYSTEM_INFO si;
        GetSystemInfo(&si);

        MEMORY_BASIC_INFORMATION info;
        std::vector<char> chunk;
        char* p = (char*)STACK_START;
        
        size_t k = 0;

        while(p < si.lpMaximumApplicationAddress)
        {
            if(!VirtualQueryEx(process, p, &info, sizeof(info)))
            {
                printf("Virtual query fail\n");
                p += info.RegionSize;
                continue;
            }

            if(info.State != MEM_COMMIT)
            {
                printf("Skipped page(invalid acces)\n");
                p += info.RegionSize;
                continue;
            }

            p = (char*)info.BaseAddress;
            chunk.resize(info.RegionSize);

            SIZE_T bytesRead;
            if(!ReadProcessMemory(process, p, &chunk[0], chunk.size(), &bytesRead))
            {
                printf("Read fail\n");
                p += info.RegionSize;
                continue;
            }

            //Checking previous finds
            while(p <= adresses[k] && adresses[k] < p + info.RegionSize - len){
                if(memcmp(data, &chunk[adresses[k] - p], len) == 0){
                    temp.push_back(adresses[k]);
                }
                k++;
            }
            p += info.RegionSize;
        }
    }

    printf("Checking adresses...\n");

    adresses = std::move(temp);
    
    CloseHandle(process);
}

void SetAdressData(DWORD pid,char* adress,const char* newData,size_t len){

    HANDLE process = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION ,FALSE,pid);
    if(process){
        SIZE_T bytesWritten;
        printf("%d\n",*(int*)newData);
        if(WriteProcessMemory(process,adress,newData,len,&bytesWritten)){
            printf("Written! \n");
        }
        else{
            printf("Fail! \n");
        }
    }
    CloseHandle(process);
}

int main(){

    #ifdef _WIN64
        printf("WIN64 detected\n");
    #endif

    ///////////////
    // DATA SPOT //
    //////////////
    int data = 1;
    int dataNew = 99;
    char processName[30] = "DarkSoulsIII";//"DarkSoulsIII";

    printf("Write selected process name:\n");
    //scanf("%s",&processName);
    
    printf("Write numerical data target:\n");
    std::cin >> data;
    
    printf("Enter new data:\n");
    //std::cin >> dataNew;

    std::cin.get();

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            char exeName[30];
            sprintf(exeName,"%s.exe",processName);

            if(stricmp(exeName,(const char*)entry.szExeFile) == 0){
                printf("Found process %s \n", exeName);
                DWORD process = entry.th32ProcessID;
                if(!process){
                    printf("Couldnt open process");
                    std::cin.get();
                }
                std::vector<char*> adresses;

                /////////////////
                //Custom adress//
                /////////////////
               GetAddressOfData(process,(char*)&data,sizeof(data),adresses);
                //adresses.push_back(reinterpret_cast<char*>(0x00007FF3C46930A8));
                /*
                00007FF3B8154428
00007FF3C4691B01
00007FF3C46930A8
                */
                if(adresses.size())
                {
                    while(adresses.size() > 3){
                        std::cout << "Found" << adresses.size() << " adresses:\n";

                        if(adresses.size() < 10)
                            for(auto& a : adresses){
                                printf("%p\n",a);
                             }

                        printf("New numerical data:\n");
                        std::cin >> data;

                        CheckAddressesOfData(process,(char*)&data,sizeof(data),adresses);
                    }
                    if(!adresses.size())
                    {
                        printf("No matching data found\n");
                        return 0;
                    }

                    printf("Found adress: %p\n",adresses[0]);

                    for(auto& a : adresses)
                        SetAdressData(process,a,(char*)&dataNew,sizeof(dataNew));

                    std::cout << "Set " << data << " to new data: " << dataNew << std::endl;
                }
                else
                {
                    printf("Adress not found");
                }
            }
        }
    }
    else
    {
        printf("Error: %d",GetLastError());
    }

    CloseHandle(snapshot);

    std::cin.get();
}
