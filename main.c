#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>
#include <libgen.h>

#include "libs/libusb.h"
#include "libs/curl.h"
#include "libs/aes.h"
#include "libs/base64.h"
#include "libs/tiny-json.h"
#include "libs/md5.h"

#define ADB_CLASS 0xff
#define ADB_SUB_CLASS 0x42
#define ADB_PROTOCOL_CODE 1
#define ADB_CONNECT 0x4E584E43
#define ADB_VERSION 0x01000001
#define ADB_OPEN 0x4E45504F
#define ADB_OKAY 0x59414B4F
#define ADB_WRTE 0x45545257
#define ADB_CLSE 0x45534C43
#define ADB_MAX_DATA 1024 * 1024
#define CHUNK_SIZE 2048
#define ADB_SIDELOAD_CHUNK_SIZE 1024 * 64
#define MAX_PATH_LENGTH 256
#define MAX_FILES 100

libusb_context *ctx;
libusb_device_handle *dev_handle;

int bulk_in;
int bulk_out;
int interface_num;

char* codename;
char* version;
char* serial_num;
char* codebase;
char* branch;
char* lang;
char* region;
char* romzone;


typedef struct {
    uint32_t cmd;
    uint32_t arg0;
    uint32_t arg1;
    uint32_t len;
    uint32_t checksum;
    uint32_t magic;
} adb_usb_packet;

typedef struct {
    char *buffer;
    int len;
    int buflen;
} get_request;

static bool endpoint_is_output(uint8_t endpoint) {
    return (endpoint & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_OUT;
}

int check_device(libusb_device *dev) {

    struct libusb_device_descriptor desc;
    int r = libusb_get_device_descriptor(dev, &desc);
    if (r != LIBUSB_SUCCESS) {
        printf("Failed to get device descriptor\n");
        return 1;
    }

    struct libusb_config_descriptor *configs;
    r = libusb_get_active_config_descriptor(dev, &configs);
    if (r != LIBUSB_SUCCESS) {
        printf("Failed to get active config descriptor\n");
        return 1;
    }

    bulk_in = -1;
    bulk_out = -1;
    interface_num = -1;

    for (int i = 0; i < configs->bNumInterfaces; i++) {
        struct libusb_interface intf = configs->interface[i];
        if (intf.num_altsetting == 0) {
            continue;
        }

        interface_num = i;
        struct libusb_interface_descriptor intf_desc = intf.altsetting[0];
        if (!(intf_desc.bInterfaceClass == ADB_CLASS && intf_desc.bInterfaceSubClass == ADB_SUB_CLASS && intf_desc.bInterfaceProtocol == ADB_PROTOCOL_CODE)) {
            continue;
        }

        if (intf.num_altsetting != 1) {
            continue;
        }

        for(int endpoint_num = 0; endpoint_num < intf_desc.bNumEndpoints; endpoint_num++) {
            struct libusb_endpoint_descriptor ep = intf_desc.endpoint[endpoint_num];
            const uint8_t endpoint_addr = ep.bEndpointAddress;
            const uint8_t endpoint_attr = ep.bmAttributes;
            const uint8_t transfer_type = endpoint_attr & LIBUSB_TRANSFER_TYPE_MASK;

            if (transfer_type != LIBUSB_TRANSFER_TYPE_BULK) {
                continue;
            }

            if (endpoint_is_output(endpoint_addr) && bulk_out == -1) {
                bulk_out = endpoint_addr;
            } else if (!endpoint_is_output(endpoint_addr) && bulk_in == -1) {
                bulk_in = endpoint_addr;
            }

            if(bulk_out != -1 && bulk_in != -1) {
                return 0;
            }
        }
    }

    return 1;
}

int scan_for_device_from_fd(int fd) {

    libusb_set_option(NULL, LIBUSB_OPTION_NO_DEVICE_DISCOVERY);
    int r = libusb_init(&ctx);
    if (r != LIBUSB_SUCCESS)
    {
        printf("Failed to init libusb\n");
        return 1;
    }
    libusb_set_option(NULL, LIBUSB_OPTION_NO_DEVICE_DISCOVERY);
    libusb_wrap_sys_device(ctx, (intptr_t) fd, &dev_handle);
    libusb_device *dev = libusb_get_device(dev_handle);
    if(check_device(dev) == 0) 
    {   
        r = libusb_claim_interface(dev_handle, interface_num);
        if(r != LIBUSB_SUCCESS) {
            printf("Failed to claim interface\n");
            return 1;
        }
    }
    return 0;
}

int scan_for_device() {
    int r = libusb_init(&ctx);
    if (r != LIBUSB_SUCCESS)
    {
        printf("Failed to init libusb\n");
        return 1;
    }

    libusb_device **devs= NULL;
    libusb_device *dev= NULL;
    ssize_t cnt = libusb_get_device_list(ctx, &devs);
    if (cnt < 0) {
        printf("Failed to get device list\n");
        return 1;
    }

    int i = 0;
    bool found = false;
    while ((dev = devs[i++]) != NULL) {
        if(check_device(dev) == 0) 
        {   
            found = true;
            r = libusb_open(dev, &dev_handle);
            if(r != LIBUSB_SUCCESS) {
                printf("Failed to open usb device\n");
                return 1;
            }
            r = libusb_claim_interface(dev_handle, interface_num);
            if(r != LIBUSB_SUCCESS) {
                printf("Failed to claim interface\n");
                return 1;
            }
            break;
        }
    }

    libusb_free_device_list(devs, 1);
    
    if (found) {
        return 0;
    } else {
        return 1;
    };
}


int usb_read(void *data, int datalen) {
    int read_len;
    libusb_set_option(NULL, LIBUSB_OPTION_NO_DEVICE_DISCOVERY);
    int r = libusb_bulk_transfer(dev_handle, bulk_in, data, datalen, &read_len, 1000);
    if (r != LIBUSB_SUCCESS) {
        // printf("usb bulk read error\n");
        return -1;
    }
    return read_len;
}

int usb_write(void *data, int datalen) {
    int write_len;
    libusb_set_option(NULL, LIBUSB_OPTION_NO_DEVICE_DISCOVERY);
    int r = libusb_bulk_transfer(dev_handle, bulk_out, data, datalen, &write_len, 1000);
    if (r != LIBUSB_SUCCESS) {
        // printf("usb bulk write error\n");
        return -1;
    }
    return write_len;
}


int send_command(uint32_t cmd, uint32_t arg0, uint32_t arg1, void *data, int datalen) {
    adb_usb_packet pkt;
    pkt.cmd = cmd;
    pkt.arg0 = arg0;
    pkt.arg1 = arg1;
    pkt.len = datalen;
    pkt.checksum = 0;
    pkt.magic = cmd ^ 0xffffffff;

    if(usb_write(&pkt, sizeof(pkt)) == -1) {
        return 1;
    } 

    if(datalen > 0) {
        if(usb_write(data, datalen) == -1) {
            return 1;
        }
    }
    return 0;
}

int recv_packet(adb_usb_packet *pkt, void* data, int *data_len) {
    if(!usb_read(pkt, sizeof(adb_usb_packet))) {
        return 1;
    }

    if(pkt->len > 0) {
        if(!usb_read(data, pkt->len)) {
            return 1;
        }
    }

    *data_len = pkt->len;
    return 0;
}

int send_recovery_commands(char* command, char* response) {
    int cmd_len = strlen(command);
    char cmd[cmd_len + 1];
    memcpy(cmd, command, cmd_len);
    cmd_len++;
    cmd[cmd_len] = 0;

    if(send_command(ADB_OPEN, 1, 0, cmd, cmd_len)) {
        printf("device not accept connect request\n");
        return 1;
    }

    adb_usb_packet pkt;
    char data[512];
    int data_len;
    recv_packet(&pkt, data, &data_len); 

    if(recv_packet(&pkt, response, &data_len)) {
        printf("Failed to get info from device\n");
        return 1;
    }

    response[data_len] = 0;
    if(response[data_len - 1] == '\n')
        response[data_len - 1] = 0;

    recv_packet(&pkt, data, &data_len); 
    return 0;

}

int connect_device_read_info(bool read_info) {
    if(send_command(ADB_CONNECT, ADB_VERSION, ADB_MAX_DATA, "host::\x0", 7)) {
        printf("device not accept connect request\n");
        return 1;
    }

    char buf[512];
    int buf_len;
    adb_usb_packet pkt;
    int try_count = 10;
    while (try_count > 0) {
        if(recv_packet(&pkt, buf, &buf_len)) {
            printf("Failed to read response from device\n");
            return 1;
        }
        if(pkt.cmd == ADB_CONNECT) break;
        try_count--;
    }

    if(try_count == 0) {
        printf("Device doesn't send correct response\n");
        return 1;
    }

    buf[buf_len] = 0;
    if(memcmp(buf, "sideload::", 10)){
        return 1;
    }

    if(!read_info) {
        return 0;
    }  

    char *commands[] = {"getdevice:", "getversion:", "getsn:", "getcodebase:", "getbranch:", "getlanguage:", "getregion:", "getromzone:"};
    const char *error_message = "Failed to execute ";
    void *params[] = {codename, version, serial_num, codebase, branch, lang, region, romzone};

    for (int i = 0; i < 8; i++) {
        if (send_recovery_commands(commands[i], params[i])) {
            printf("%s%s", error_message, commands[i]);
            return 1;
        }
    }

    return 0;
}

size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    size_t realsize = size * nmemb; 
    get_request *req = (get_request *) userdata;
    while (req->buflen < req->len + realsize + 1)
    {
        req->buffer = realloc(req->buffer, req->buflen + CHUNK_SIZE);
        req->buflen += CHUNK_SIZE;
    }
    memcpy(&req->buffer[req->len], ptr, realsize);
    req->len += realsize;
    req->buffer[req->len] = 0;

    return realsize;
}

int fileexists(const char *fname)
{
    FILE *file;
    if ((file = fopen(fname, "r")))
    {
        fclose(file);
        return 1;
    }
    return 0;
}

char* generate_md5_hash(char* filename) {
    FILE *fp = fopen(filename, "r");
    uint8_t hash[16];

    md5File(fp, hash);
    char *og_ptr = malloc(32);
    char *ptr = og_ptr;
    for(int i = 0; i < 16; i++) {
        ptr += sprintf(ptr, "%02x", hash[i]);
    }
    return og_ptr;
}

int generate_firmware_sign(char* signfile) {
    char* pkg_hash;
    bool checkrom;
    if (signfile == NULL) {
        char md5_input[33]; 
        printf("\nPlease enter the MD5 string: ");
        scanf("%32s", md5_input);
        checkrom = true;
        pkg_hash = md5_input;
    } else {
        checkrom = false;
        printf("\nGenerating MD5 hash ...\n");
        pkg_hash = generate_md5_hash(signfile);
    }
    

    const uint8_t key[16] = { 0x6D, 0x69, 0x75, 0x69, 0x6F, 0x74, 0x61, 0x76, 0x61, 0x6C, 0x69, 0x64, 0x65, 0x64, 0x31, 0x31};
    const uint8_t iv[16] = { 0x30, 0x31, 0x30, 0x32, 0x30, 0x33, 0x30, 0x34, 0x30, 0x35, 0x30, 0x36, 0x30, 0x37, 0x30, 0x38};

    char json_request[1024];
    memset(json_request, 0, 1024);
    sprintf(json_request, "{\n\t\"d\" : \"%s\",\n\t\"v\" : \"%s\",\n\t\"c\" : \"%s\",\n\t\"b\" : \"%s\",\n\t\"sn\" : \"%s\",\n\t\"r\" : \"GL\",\n\t\"l\" : \"en-US\",\n\t\"f\" : \"1\",\n\t\"id\" : \"\",\n\t\"options\" : {\n\t\t\"zone\" : %s\n\t},\n\t\"pkg\" : \"%s\"\n}", codename, version, codebase, branch, serial_num, romzone, pkg_hash);

    if (!checkrom) {
        free(pkg_hash);
    }

    int len = strlen(json_request);
    int mod_len = 16 - (len % 16);
    if (mod_len > 0) {
        for(int i = 0; i < mod_len; i++) 
            json_request[len + i] = (char)mod_len;
        
        len = len + mod_len;
    }

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_encrypt_buffer(&ctx, (uint8_t *)json_request, len);

    int b64_len = b64_encodedLength(len);
    char out_buf[b64_len];
    memset(out_buf, 0, b64_len);
    b64_encode((uint8_t *)json_request, len, (uint8_t *)out_buf);

    curl_global_init(CURL_GLOBAL_ALL);
    CURL* curl = curl_easy_init();

    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "clientId: MITUNES");
    headers = curl_slist_append(headers, "Connection: Keep-Alive");
    headers = curl_slist_append(headers, "Accept-Encoding: identity");
    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");

    char *post_buf = malloc(4096);
    char *json_post_data = curl_easy_escape(curl, out_buf, strlen(out_buf));
    sprintf(post_buf, "q=%s&t=&s=1", json_post_data);
    get_request req = {.buffer = NULL, .len = 0, .buflen = 0};

    curl_easy_setopt(curl, CURLOPT_URL, "http://update.miui.com/updates/miotaV3.php");
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "MiTunes_UserAgent_v3.0");
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_buf);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    req.buffer = malloc(CHUNK_SIZE);
    req.buflen = CHUNK_SIZE;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&req);
    
    printf("\nSending request ...\n");
    curl_easy_perform(curl);
    
    int result = 1;
    long status_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status_code);
    if (status_code == 200) {
        curl_free(json_post_data);
        json_post_data = curl_easy_unescape(curl, req.buffer, req.len, &len);
        
        memset(post_buf, 0, 4096);
        b64_len = b64_decode((uint8_t *)json_post_data, len,(uint8_t*)post_buf);
        AES_init_ctx_iv(&ctx, key, iv);
        AES_CBC_decrypt_buffer(&ctx, (uint8_t *)post_buf, b64_len);

        post_buf[b64_len - post_buf[b64_len - 1]] = 0;
        // printf("Response after decryption: %s\n", post_buf);
        json_t mem[64];
        json_t const* json = json_create(post_buf, mem, sizeof mem / sizeof *mem);
        if(!json) {
            printf("Failed to parse json\n");
            goto out;
        } 

        json_t const* pkgRom = json_getProperty(json, "PkgRom");
        if(!pkgRom) {
            if (checkrom) {
                printf("\n\033[0;31mThis ROM can't be installed\n\033[0m\n");
                goto out;
            }
            printf("\n\033[0;31mValidation Rom Failed\n\033[0m");
            goto out;
        }

        char const* validate = json_getPropertyValue(pkgRom, "Validate");
        if (!validate) {
            printf("\n\033[0;31mValidation Failed\n\033[0m");
            goto out;
        } else {
            if (checkrom) {
                printf("\n\033[0;32mThis ROM can be installed\n\033[0m\n");
                goto out;
            }
        }

        json_t const* erase = json_getProperty(pkgRom, "Erase");
        if (erase) {
            int erase_value = json_getInteger(erase);
            printf("\nErase: %d\n", erase_value);
        } else {
            printf("\nErase Value: Not found\n");
        }

        char user_input;
        printf("\nDo you want to continue? (y/n): ");
        scanf(" %c", &user_input); 
        if (user_input == 'n' || user_input == 'N') {
            goto out;  
        }

        FILE* fp = fopen("validate.key", "w");
        fwrite(validate, 1, strlen(validate), fp);
        fclose(fp);
        printf("\n\033[0;32mValidation Rom Done\n\033[0m\n");
        curl_free(json_post_data);
        free(post_buf);
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
        free(req.buffer);
        return 0;
    }
out:
    curl_free(json_post_data);
    free(post_buf);
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    free(req.buffer);
    return result;
}

int start_sideload(const char *sideload_file) {
    
    FILE *fp = fopen("validate.key", "r");
    fseek(fp, 0, SEEK_END);
    long validate_file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char validate[validate_file_size];
    fread(validate, 1, validate_file_size, fp);
    fclose(fp);

    fp = fopen(sideload_file, "r");
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);  
    char sideload_host_command[128 + validate_file_size];
    memset(sideload_host_command, 0, 128 + validate_file_size);
    sprintf(sideload_host_command, "sideload-host:%ld:%d:%s:0", file_size, ADB_SIDELOAD_CHUNK_SIZE, validate);
    send_command(ADB_OPEN, 1, 0, sideload_host_command, strlen(sideload_host_command) + 1);

    uint8_t *work_buffer = malloc(ADB_SIDELOAD_CHUNK_SIZE);
    char dummy_data[64];
    int dummy_data_size;
    adb_usb_packet pkt;
    long total_sent = 0;

    printf("\nRom Size: %.2f GB\n", (float)file_size / (1024 * 1024 * 1024)); 

    while (1)
    {
        pkt.cmd = 0;
        recv_packet(&pkt, dummy_data, &dummy_data_size);
        if(pkt.cmd == ADB_OKAY) send_command(ADB_OKAY, pkt.arg1, pkt.arg0, NULL, 0);
        if(pkt.cmd != ADB_WRTE) continue;

        dummy_data[dummy_data_size] = 0;
        if(dummy_data_size > 8) {
            printf("\n%s\n", dummy_data);
            break;
        }
        long block = strtol(dummy_data, NULL, 10);
        long offset = block * ADB_SIDELOAD_CHUNK_SIZE;

        if (offset > file_size) break;
        int to_write = ADB_SIDELOAD_CHUNK_SIZE;
        if(offset + ADB_SIDELOAD_CHUNK_SIZE > file_size) 
            to_write = file_size - offset;
        
        fseek(fp, offset, SEEK_SET);
        fread(work_buffer, 1, to_write, fp);
        send_command(ADB_WRTE, pkt.arg1, pkt.arg0, work_buffer, to_write);
        send_command(ADB_OKAY, pkt.arg1, pkt.arg0, NULL, 0);

        total_sent += to_write;
        float sent_gb = (float)total_sent / (1024 * 1024 * 1024);
        sent_gb /= 2;
        printf("\rSent: %.2f GB", sent_gb);
        fflush(stdout);
    }
    
    free(work_buffer);
    fclose(fp);
    return 0;
}

char* select_rom() {
    char input[MAX_PATH_LENGTH];

    while (1) {
        printf("\nenter the path of the ROM.zip you want to flash: ");
        if (fgets(input, sizeof(input), stdin) != NULL) {
            input[strcspn(input, "\n")] = 0;
            if (strlen(input) > 0) {
                if (access(input, F_OK) == 0) {
                    return strdup(input);
                } else {
                    printf("\nThe file does not exist!\n");
                }
            } else {
                printf("\nInvalid path!\n");
            }
        } else {
            printf("\nInvalid input!\n");
        }
    }
}


void printMenu() {
    printf("\033[90m\nMiAssistantTool version 1.0 For issues or feedback:\n- GitHub: github.com/offici5l/MiAssistantTool/issues\n- Telegram: t.me/Offici5l_Group\n\033[0m\n");

    printf("━ \033[1;32m1\033[0m Read-Info\n\n");
    printf("━ \033[1;32m2\033[0m Check-ROM-Compatibility(With MD5)\n\n");
    printf("━ \033[1;32m3\033[0m Flash-Official-Recovery-ROM\n\n");
    printf("━ \033[1;32m4\033[0m Format-Data\n\n");

    printf("\nEnter your \033[1;32mchoice\033[0m: ");
}

int getUserChoice() {
    printMenu();
    int choice;
    if (scanf("%d", &choice) != 1 || (choice < 1 || choice > 4)) {
        printf("\nInvalid choice. exiting...\n");
        exit(1);
    }
    return choice;
}


char* list_usb_devices() {
    FILE* fp;
    char buffer[1024];
    char* result = malloc(1024 * sizeof(char));

    fp = popen("termux-usb -l", "r");
    if (fp == NULL) {
        printf("Failed to run command\n");
        exit(1);
    }

    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        strcat(result, buffer);
    }

    pclose(fp);
    return result;
}


void access_usb_device() {
    char* devices = list_usb_devices();

    if (strcmp(devices, "[]\n") == 0) {
        printf("No USB devices found.\n");
        free(devices);
        exit(1);
    } else {
        char* token = strtok(devices, "\"");
        token = strtok(NULL, "\"");

        char command[1024];
        sprintf(command, "termux-usb -r \"%s\"", token);
        FILE* fp = popen(command, "r");
        char result[1024];

        if (fp == NULL) {
            printf("Failed to run command\n");
            free(devices);
            exit(1);
        }

        fgets(result, sizeof(result), fp);
        pclose(fp); 
        printf("%s", result);

        if (strstr(result, "Access denied.") != NULL) {
            free(devices);
            access_usb_device();
        } else {
            char exe_path[4096];
            #ifndef _WIN32
                ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
                if (len != -1) {
                    exe_path[len] = '\0';
                } else {
                    perror("readlink");
                    free(devices);
                    exit(1);
                }
            #endif
            char* base_name = strrchr(exe_path, '/');
            if (base_name) {
                base_name++;
            } else {
                base_name = exe_path; 
            }
            sprintf(command, "termux-usb -E -e \"%s ok\" -r %s", exe_path, token);
            free(devices);
            system(command);
            exit(1); 
        }
    }
}

int main(int argc, char** argv) {

    dev_handle = NULL;
    char* rom_path = NULL;
    char buf[256];

    char* termux_env = getenv("TERMUX_VERSION");
    if (termux_env != NULL && argc == 1) {
        access_usb_device();
    }

    char *fd_s = getenv("TERMUX_USB_FD");
    if (fd_s != NULL) {
        int fd = atoi(fd_s);
        int result = scan_for_device_from_fd(fd);
        if (result != 0) {
            system("pkill -9 -f 'tcp'");
            fd_s = getenv("TERMUX_USB_FD");
            if (fd_s != NULL) {
                fd = atoi(fd_s);
                result = scan_for_device_from_fd(fd);
                if (result != 0) {
                    return 1;
                }
            } else {
                printf("\nIncorrect device\n");
                return 1;
            }
        }
    } else {
        if (scan_for_device() != 0) {
            printf("No device found\n");
            return 1;
        }
    }

    int choice = getUserChoice();
    
    codename = (char *)malloc(64);
    version = (char *)malloc(64);
    serial_num = (char *)malloc(64);
    codebase = (char *)malloc(64);
    branch = (char *)malloc(64);
    lang = (char *)malloc(64);
    region = (char *)malloc(64);
    romzone = (char *)malloc(64);

    bool connection = true;

    if(connect_device_read_info(true)) {
        printf("\nFailed to connect with device\n");
        connection = false;
    }

    if (connection) {

        switch (choice) {
            case 1:
                printf("\nDevice Information:\n"
       "-------------------\n"
       "Codename:   %s\n"
       "Version:    %s\n"
       "Serial:     %s\n"
       "Codebase:   %s\n"
       "Branch:     %s\n"
       "Language:   %s\n"
       "Region:     %s\n"
       "Romzone:    %s\n\n",
       codename, version, serial_num, codebase, branch, lang, region, romzone);
                break;
            case 2:
                generate_firmware_sign(NULL);
                break;
            case 3:
                rom_path = select_rom();
                if(rom_path) {
                    int result = generate_firmware_sign(rom_path);
                    if (result == 0) {
                        start_sideload(rom_path); 
                    }
                }
                break;
            case 4:
                send_recovery_commands("format-data:", buf);
                printf("\nDevice formatted successfully\n");
                send_recovery_commands("reboot:", buf);
                break;
            default:
                printf("Invalid choice. Exiting...\n");
                return 1;
        }

        free(codename); 
        free(version); 
        free(serial_num); 
        free(codebase); 
        free(branch); 
        free(lang); 
        free(region); 
        free(romzone); 

        if (dev_handle != NULL) {
            libusb_release_interface(dev_handle, interface_num);
            libusb_close(dev_handle);
        }
        libusb_exit(ctx);
    }
    
    return 0;

}

