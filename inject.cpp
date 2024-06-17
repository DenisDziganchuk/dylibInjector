#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/error.h>
#include <errno.h>
#include <stdlib.h>
#include <libproc.h>
#include <sys/stat.h>
#include <pthread.h>
#include <mach/mach_vm.h>

#define STACK_SIZE 65536
#define CODE_SIZE 128

char injectedCode[] =
    // "\xCC"                            // int3

    "\x55"                            // push       rbp
    "\x48\x89\xE5"                    // mov        rbp, rsp
    "\x48\x83\xEC\x10"                // sub        rsp, 0x10
    "\x48\x8D\x7D\xF8"                // lea        rdi, qword [rbp+var_8]       
    "\x31\xC0"                        // xor        eax, eax
    "\x89\xC1"                        // mov        ecx, eax                     
    "\x48\x8D\x15\x21\x00\x00\x00"    // lea        rdx, qword ptr [rip + 0x21]  
    "\x48\x89\xCE"                    // mov        rsi, rcx                     
    "\x48\xB8"                        // movabs     rax, pthread_create_from_mach_thread
    "PTHRDCRT"
    "\xFF\xD0"                        // call       rax
    "\x89\x45\xF4"                    // mov        dword [rbp+var_C], eax
    "\x48\x83\xC4\x10"                // add        rsp, 0x10
    "\x5D"                            // pop        rbp
    "\x48\xc7\xc0\x13\x0d\x00\x00"    // mov        rax, 0xD13
    "\xEB\xFE"                        // jmp        0x0
    "\xC3"                            // ret

    "\x55"                            // push       rbp                          
    "\x48\x89\xE5"                    // mov        rbp, rsp
    "\x48\x83\xEC\x10"                // sub        rsp, 0x10
    "\xBE\x01\x00\x00\x00"            // mov        esi, 0x1
    "\x48\x89\x7D\xF8"                // mov        qword [rbp+var_8], rdi    
    "\x48\x8D\x3D\x1D\x00\x00\x00"    // lea        rdi, qword ptr [rip + 0x2c]  
    "\x48\xB8"                        // movabs     rax, dlopen
    "DLOPEN__"                
    "\xFF\xD0"                        // call       rax
    "\x31\xF6"                        // xor        esi, esi
    "\x89\xF7"                        // mov        edi, esi
    "\x48\x89\x45\xF0"                // mov        qword [rbp+var_10], rax
    "\x48\x89\xF8"                    // mov        rax, rdi
    "\x48\x83\xC4\x10"                // add        rsp, 0x10
    "\x5D"                            // pop        rbp
    "\xC3"                            // ret

    "LIBLIBLIBLIB"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";


pid_t find_pid_from_process(const char* process) {
    pid_t pid_list[512];
    struct proc_bsdinfo pinfo;
    int byte_count = proc_listpids(PROC_ALL_PIDS, 0, pid_list, sizeof(pid_list));
    int proc_count = byte_count / sizeof(pid_t);
    for (int i = 0; i < proc_count; i++) {
        int read = proc_pidinfo(pid_list[i], PROC_PIDTBSDINFO, 0, &pinfo, PROC_PIDTBSDINFO_SIZE);
        if (read == PROC_PIDTBSDINFO_SIZE) {
            if (strcmp(pinfo.pbi_name, process) == 0) {
                return pinfo.pbi_pid;
            }
        }
    }
    return 0;
}

int inject(pid_t pid, const char *lib)
{
    task_t remoteTask;
    struct stat buf;

    // Check if dylib exists  
    int rc = stat(lib, &buf);
    if (rc != 0) {
        fprintf(stderr, "Unable to open library file %s (%s) - Cannot inject\n", lib, strerror(errno));
        //return (-9);
    }

    mach_error_t kr = 0;

    // Get task port of target process id
    kr = task_for_pid(mach_task_self(), pid, &remoteTask);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Unable to call task_for_pid on pid %d: %s. Cannot continue!\n", pid, mach_error_string(kr));
        return (-1);
    }

    // Allocate memory for the stack
    mach_vm_address_t remoteStack64 = (vm_address_t)NULL;
    mach_vm_address_t remoteCode64 = (vm_address_t)NULL;
    kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
        return (-2);
    }
    else {
        fprintf(stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
    }
    
    // Allocate memory for the code
    remoteCode64 = (vm_address_t)NULL;
    kr = mach_vm_allocate(remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
        return (-2);
    }

    // Patch the code by inserting correct function addresses and dylib name
    int i = 0;
    char *possiblePatchLocation = (injectedCode);
    for (i = 0; i < 0x100; i++) {
        extern void *_pthread_set_self;
        possiblePatchLocation++;

        uint64_t addrOfPthreadCreate = (uint64_t)dlsym(RTLD_DEFAULT, "pthread_create_from_mach_thread");
        uint64_t addrOfPthreadExit = (uint64_t)dlsym(RTLD_DEFAULT, "pthread_exit");
        uint64_t addrOfDlopen = (uint64_t)dlopen;

        if (memcmp(possiblePatchLocation, "PTHRDCRT", 8) == 0) {
            printf("pthread_create_from_mach_thread @%llx\n", addrOfPthreadCreate);
            memcpy(possiblePatchLocation, &addrOfPthreadCreate, 8);            
        }

        if (memcmp(possiblePatchLocation, "DLOPEN__", 6) == 0) {
            printf("dlopen @%llx\n", addrOfDlopen);
            memcpy(possiblePatchLocation, &addrOfDlopen, sizeof(uint64_t));
        }        

        if (memcmp(possiblePatchLocation, "LIBLIBLIB", 9) == 0) {
            strcpy(possiblePatchLocation, lib);
        }
    }

    // Write the patched code
    kr = mach_vm_write(remoteTask,                 // Task port
                       remoteCode64,               // Virtual Address (Destination)
                       (vm_address_t)injectedCode, // Source
                       sizeof(injectedCode));      // Length of the source

    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
        return (-3);
    }

    // Mark code as executable
    kr = vm_protect(remoteTask, remoteCode64, sizeof(injectedCode), FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

    // Mark stack as writable
    kr = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Unable to set memory permissions for remote thread: Error %s\n", mach_error_string(kr));
        return (-4);
    }

    // Create thread
    x86_thread_state64_t remoteThreadState64;

    thread_act_t remoteThread;

    memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64));

    remoteStack64 += (STACK_SIZE / 2); // Real stack
                                       //remoteStack64 -= 8;  // Needs alignment of 16

    const char *p = (const char *)remoteCode64;

    remoteThreadState64.__rip = (u_int64_t)(vm_address_t)remoteCode64;

    // Set remote Stack Pointer
    remoteThreadState64.__rsp = (u_int64_t)remoteStack64;
    remoteThreadState64.__rbp = (u_int64_t)remoteStack64;

    printf("Remote Stack 64  0x%llx, Remote code is %p\n", remoteStack64, p);

    // Create thread and launch it
    kr = thread_create_running(remoteTask, x86_THREAD_STATE64,
                               (thread_state_t)&remoteThreadState64, x86_THREAD_STATE64_COUNT, &remoteThread);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Unable to create remote thread: error %s", mach_error_string(kr));
        return (-3);
    }

    // Wait for the mach thread to finish
    mach_msg_type_number_t thread_state_count = x86_THREAD_STATE64_COUNT;
    for (;;) {
	    kr = thread_get_state(remoteThread, x86_THREAD_STATE64, (thread_state_t)&remoteThreadState64, &thread_state_count);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "Error getting stub thread state: error %s", mach_error_string(kr));
            break;
        }
        
        if (remoteThreadState64.__rax == 0xD13) {
            printf("Stub thread finished\n");
            kr = thread_terminate(remoteThread);
            if (kr != KERN_SUCCESS) {
                fprintf(stderr, "Error terminating stub thread: error %s", mach_error_string(kr));
            }
            break;
        }
    }

    return 0;
}

int main(int argc, char *argv[]) {
    char path[1024];
    char process[1024];
    if (argc == 1) {
        printf("Enter path of the dylib to be injected:\n");
        scanf("%s", path);

        printf("Enter name of process that the dylib should be injected in:\n");
        scanf("%s", process);
    }
    else if (argc == 2) {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            printf("Dylib Injector\n\nUsage:\n       sudo ./dylibInjector\n       sudo ./dylibInjector -d [path to dylib] -p [process name]\n       sudo ./dylibInjector --dylib [path to dylib] --process [process name]");
            return 1;
        }
        else {
            printf("Arguments not recognized! Use -h or --help for help!\n");
            return 1;
        }
    }
    else if (argc == 5) {
        if (strcmp(argv[1], "-d") == 0 && strcmp(argv[3], "-p") == 0 || strcmp(argv[1], "--dylib") == 0 && strcmp(argv[3], "--process") == 0) {
            strcpy(path, argv[2]);
            strcpy(process, argv[4]);
        }
        else {
            printf("Arguments not recognized! Use -h or --help for help!\n");
            return 1;
        }
    }
    else {
        printf("Incorrect number of arguments! Use -h or --help for help!\n");
        return 1;
    }

    pid_t pid = find_pid_from_process(process);
    if (pid == 0) {
        printf("Unable to find process!\n");
        return 1;
    }
    printf("Process id of %s is %d.\n", process, pid);
    inject(pid, path);
    return 0;
}