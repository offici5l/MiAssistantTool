#ifdef _WIN32
    #include <windows.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>
#include <libgen.h>

#include <libusb-1.0/libusb.h>
#include <curl/curl.h>

#include "libs/aes.h"
#include "libs/base64.h"
#include "libs/tiny-json.h"
#include "libs/md5.h"

int bulk_in;
int bulk_out;
int interface_num;

libusb_context *ctx;
libusb_device_handle *dev_handle;

char response[4096]; 


int getUserChoice() {
    int choice;
    char choice_str[10];
    FILE *file;

    if ((file = fopen("choi.tmp", "r")) != NULL) {
        fclose(file);
        return 0;
    }

    printf("\033[90m\nMiAssistantTool version 1.1 For issues or feedback:\n- GitHub: github.com/offici5l/MiAssistantTool/issues\n- Telegram: t.me/Offici5l_Group\n\033[0m\n");

    do {
        printf("\n  1 = Read Info\n  2 = Check ROM Compatibility (MD5)\n  3 = Flash Official Recovery ROM\n  4 = Format Data\n  5 = Reboot\n\n   Enter your choice: ");
        if (scanf("%d", &choice) != 1 || choice < 1 || choice > 5) {
            printf("\nInvalid choice! Please enter a valid option.\n");
            while (getchar() != '\n');
        } else {
            break;
        }
    } while (1);

    sprintf(choice_str, "%d", choice);
    file = fopen("choi.tmp", "w");
    if (!file) {
        perror("Error opening file");
        return 1;
    }
    if (fprintf(file, "%s", choice_str) < 0) {
        perror("Error writing to file");
        fclose(file);
        return 1;
    }
    fclose(file);
    return 0;
}


int check_device(libusb_device *dev) {
    
    struct libusb_device_descriptor desc;

    int r = libusb_get_device_descriptor(dev, &desc);
    if (r != LIBUSB_SUCCESS) {
        return 1;
    }

    // mi assistant mode = 0x4e11 ?
    // fprintf(stdout, "  Product ID: 0x%04x\n", desc.idProduct);
    
    struct libusb_config_descriptor *configs;
    r = libusb_get_active_config_descriptor(dev, &configs);
    if (r != LIBUSB_SUCCESS) {
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
        
        if (!(intf_desc.bInterfaceClass == 0xff && intf_desc.bInterfaceSubClass == 0x42 && intf_desc.bInterfaceProtocol == 1)) {
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
            if ((endpoint_addr & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_OUT && bulk_out == -1) {
                bulk_out = endpoint_addr;
            } else if ((endpoint_addr & LIBUSB_ENDPOINT_DIR_MASK) != LIBUSB_ENDPOINT_OUT && bulk_in == -1) {
                bulk_in = endpoint_addr;
            }
            if(bulk_out != -1 && bulk_in != -1) {
                return 0;
            }
        }
    }
    return 1;
}



int scan_for_device() {
    getUserChoice();
    
    int r = libusb_init(&ctx);
    if (r != LIBUSB_SUCCESS) {
        fprintf(stderr, "libusb_init failed: %s\n", libusb_strerror(r));
        return 1;
    }

    libusb_device **devs = NULL;
    ssize_t cnt = libusb_get_device_list(ctx, &devs);
    if (cnt < 0) {
        fprintf(stderr, "libusb_get_device_list failed: %s\n", libusb_strerror(cnt));
        libusb_exit(ctx);
        return 1;
    }

    int i = 0;
    libusb_device *dev = NULL;
    while ((dev = devs[i++]) != NULL && check_device(dev) != 0);
    
    if (dev) {
        r = libusb_open(dev, &dev_handle);
        if (r != LIBUSB_SUCCESS) {
            fprintf(stderr, "libusb_open failed: %s\n", libusb_strerror(r));
            libusb_free_device_list(devs, 1);
            libusb_exit(ctx);
            return 1;
        }
        
        r = libusb_claim_interface(dev_handle, interface_num);
        if (r != LIBUSB_SUCCESS) {
            fprintf(stderr, "libusb_claim_interface failed: %s\n", libusb_strerror(r));
            libusb_free_device_list(devs, 1);
            libusb_close(dev_handle);
            libusb_exit(ctx);
            return 1;
        }

        libusb_free_device_list(devs, 1);
        return 0; // Success
    } else {
        fprintf(stderr, "No device found or device check failed.\n");
        libusb_free_device_list(devs, 1);
        libusb_exit(ctx);
        return 1;
    }
}


int connect_usb_device() {
    if (!getenv("TERMUX_OK")) {
        system("pkill -9 -f 'tcp'");
        getUserChoice();
        FILE *fp;
        char result[1024];
        int is_empty;
        while (1) {
            is_empty = 1;
            fp = popen("termux-usb -l | tr -d '[]\\\"' | xargs -I{} $PREFIX/libexec/termux-api Usb -a permission --ez request true --es device {}", "r");
            while (fgets(result, sizeof(result), fp) != NULL) {
                result[strcspn(result, "\n")] = '\0';
                if (strcmp(result, "yes") == 0) {
                    #ifndef _WIN32
                          setenv("TERMUX_OK", "true", 1);
                    #endif
                    char command[1024];
                    snprintf(command, sizeof(command), "termux-usb -E -e \"%s\" -r $(termux-usb -l | tr -d '[]\\\"')", getenv("_"));
                    system(command);
                    exit(0);
                } else if (strcmp(result, "no") == 0) {
                    printf("\nGrant permission to termux-api\n");
                    is_empty = 0;
                    continue;
                }
            }
            if (is_empty) {
                return 1;
            }
        }
    } else {
        int fd = atoi(getenv("TERMUX_USB_FD"));
        libusb_set_option(NULL, LIBUSB_OPTION_NO_DEVICE_DISCOVERY);
        int r = libusb_init(&ctx);
        if (r != LIBUSB_SUCCESS)
        {   
            return 1;
        }
        libusb_set_option(NULL, LIBUSB_OPTION_NO_DEVICE_DISCOVERY);
        libusb_wrap_sys_device(ctx, (intptr_t) fd, &dev_handle);
        libusb_device *dev = libusb_get_device(dev_handle);
        if(check_device(dev) == 0) 
        {   
            r = libusb_claim_interface(dev_handle, interface_num);
            if(r != LIBUSB_SUCCESS) {
            return 1;
            }
        } else {
             return 1;
        }
    }
    return 0;
}

typedef struct {
    uint32_t cmd;
    uint32_t arg0;
    uint32_t arg1;
    uint32_t len;
    uint32_t checksum;
    uint32_t magic;
} adb_usb_packet;

int usb_read(void *data, int datalen) {
    int read_len;
    libusb_set_option(NULL, LIBUSB_OPTION_NO_DEVICE_DISCOVERY);
    int r = libusb_bulk_transfer(dev_handle, bulk_in, data, datalen, &read_len, 1000);
    if (r != LIBUSB_SUCCESS) {
        return -1;
    }
    return read_len;
}

int usb_write(void *data, int datalen) {
    int write_len;
    libusb_set_option(NULL, LIBUSB_OPTION_NO_DEVICE_DISCOVERY);
    int r = libusb_bulk_transfer(dev_handle, bulk_out, data, datalen, &write_len, 1000);
    if (r != LIBUSB_SUCCESS) {
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

char* send_recovery_commands(char* command) {
 

    int cmd_len = strlen(command);
    char cmd[cmd_len + 1];
    memcpy(cmd, command, cmd_len);
    cmd[cmd_len] = 0;

    if (send_command(0x4E45504F, 1, 0, cmd, cmd_len)) {
        printf("device not accept connect request\n");
        return NULL;
    }

    adb_usb_packet pkt;
    char data[512];
    int data_len;
    recv_packet(&pkt, data, &data_len); 

    if (recv_packet(&pkt, response, &data_len)) {
        printf("Failed to get info from device\n");
        return NULL;
    }
    
    response[data_len] = 0;

    if (response[data_len - 1] == '\n')
        response[data_len - 1] = 0;

    recv_packet(&pkt, data, &data_len); 
    return response;
}



const char *generate_firmware_sign(const char *md5) {

     char device[50], version[50], codebase[50], branch[50], sn[50], romzone[50];

    strncpy(device, send_recovery_commands("getdevice:"), sizeof(device) - 1);
    strncpy(version, send_recovery_commands("getversion:"), sizeof(version) - 1);
    strncpy(codebase, send_recovery_commands("getcodebase:"), sizeof(codebase) - 1);
    strncpy(branch, send_recovery_commands("getbranch:"), sizeof(branch) - 1);
    strncpy(sn, send_recovery_commands("getsn:"), sizeof(sn) - 1);
    strncpy(romzone, send_recovery_commands("getromzone:"), sizeof(romzone) - 1);

    const uint8_t key[16] = { 0x6D, 0x69, 0x75, 0x69, 0x6F, 0x74, 0x61, 0x76, 0x61, 0x6C, 0x69, 0x64, 0x65, 0x64, 0x31, 0x31 };
    const uint8_t iv[16] = { 0x30, 0x31, 0x30, 0x32, 0x30, 0x33, 0x30, 0x34, 0x30, 0x35, 0x30, 0x36, 0x30, 0x37, 0x30, 0x38 };

    char json_request[1024];
    memset(json_request, 0, sizeof(json_request));

    sprintf(json_request, "{\n\t\"d\" : \"%s\",\n\t\"v\" : \"%s\",\n\t\"c\" : \"%s\",\n\t\"b\" : \"%s\",\n\t\"sn\" : \"%s\",\n\t\"r\" : \"GL\",\n\t\"l\" : \"en-US\",\n\t\"f\" : \"1\",\n\t\"id\" : \"\",\n\t\"options\" : {\n\t\t\"zone\" : %s\n\t},\n\t\"pkg\" : \"%s\"\n}", device, version, codebase, branch, sn, romzone, md5);

    int len = strlen(json_request);
    int mod_len = 16 - (len % 16);
    if (mod_len > 0) {
        memset(json_request + len, mod_len, mod_len);
        len += mod_len;
    }

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_encrypt_buffer(&ctx, (uint8_t *)json_request, len);

    int b64_encoded_len = b64_encodedLength(len);
    char encoded_buf[b64_encoded_len];
    memset(encoded_buf, 0, sizeof(encoded_buf));
    b64_encode((uint8_t *)json_request, len, (uint8_t *)encoded_buf);

    CURL *curl = curl_easy_init();
    if (!curl) {
        return NULL;
    }

    char post_buf[4096];
    char *json_post_data = curl_easy_escape(curl, encoded_buf, strlen(encoded_buf));
    if (!json_post_data) {
        curl_easy_cleanup(curl);
        return NULL;
    }
    snprintf(post_buf, sizeof(post_buf), "q=%s&t=&s=1", json_post_data);
    curl_free(json_post_data);

    FILE *response_file = fopen("response.tmp", "wb");
    if (!response_file) {
        curl_easy_cleanup(curl);
        return NULL;
    }

    curl_easy_setopt(curl, CURLOPT_URL, "http://update.miui.com/updates/miotaV3.php");
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "MiTunes_UserAgent_v3.0");
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_buf);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fwrite);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response_file);

    printf("\nSending request ...\n");
    CURLcode res = curl_easy_perform(curl);

    fclose(response_file);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        return NULL;
    }

    // Read response from file
    FILE *response_file_read = fopen("response.tmp", "rb");
    if (!response_file_read) {
        return NULL;
    }

    fseek(response_file_read, 0, SEEK_END);
    long response_size = ftell(response_file_read);
    fseek(response_file_read, 0, SEEK_SET);

    char *response_buffer = malloc(response_size + 1);
    if (!response_buffer) {
        fclose(response_file_read);
        return NULL;
    }
    fread(response_buffer, 1, response_size, response_file_read);
    response_buffer[response_size] = '\0';
    fclose(response_file_read);

    int decoded_len = b64_decode((uint8_t *)response_buffer, response_size, (uint8_t *)post_buf);
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_decrypt_buffer(&ctx, (uint8_t *)post_buf, decoded_len);

    free(response_buffer);
    remove("response.tmp");

    post_buf[decoded_len - post_buf[decoded_len - 1]] = '\0';
    // printf("Response after decryption: %s\n", post_buf);
    json_t mem[64];
    json_t const *json = json_create(post_buf, mem, sizeof(mem) / sizeof(*mem));
    json_t const *pkgRom = json_getProperty(json, "PkgRom");
    if (!pkgRom) {
        printf("\nThis ROM can't be installed\n\n");
        return NULL;
    }
    char const* validate = json_getPropertyValue(pkgRom, "Validate");
    if (validate) {
        printf("\nThis ROM can be installed\n\n");
    }
    return validate ? validate : NULL;
}

int start_sideload(const char *sideload_file, const char *validate) {

    printf("\n\n");
    FILE *fp = fopen(sideload_file, "r");
    if (!fp) {
        perror("Failed to open file");
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);  
    char sideload_host_command[128 + strlen(validate)];
    memset(sideload_host_command, 0, sizeof(sideload_host_command));
    sprintf(sideload_host_command, "sideload-host:%ld:%d:%s:0", file_size, 1024 * 64, validate);

    send_command(0x4E45504F, 1, 0, sideload_host_command, strlen(sideload_host_command) + 1);

    uint8_t *work_buffer = malloc(1024 * 64);
    if (!work_buffer) {
        perror("Failed to allocate memory");
        fclose(fp);
        return 1;
    }

    char dummy_data[64];
    int dummy_data_size;
    adb_usb_packet pkt;
    long total_sent = 0;

    while (1) {
        pkt.cmd = 0;
        recv_packet(&pkt, dummy_data, &dummy_data_size);

        dummy_data[dummy_data_size] = 0;
        if(dummy_data_size > 8) {
            printf("\n\n%s\n\n", dummy_data);
            break;
        }

        if (pkt.cmd == 0x59414B4F) {
            send_command(0x59414B4F, pkt.arg1, pkt.arg0, NULL, 0);
        }

        if (pkt.cmd == 0x00000000 && total_sent > 0) {
            //struct timespec ts = {6, 0};
            //nanosleep(&ts, NULL);
            //continue;
        }

        if (pkt.cmd != 0x45545257) {
            continue;
        }

        long block = strtol(dummy_data, NULL, 10);
        long offset = block * 1024 * 64;
        if (offset > file_size) break;
        int to_write = 1024 * 64;
        if(offset + 1024 * 64 > file_size) 
            to_write = file_size - offset;        
        fseek(fp, offset, SEEK_SET);
        fread(work_buffer, 1, to_write, fp);
        send_command(0x45545257, pkt.arg1, pkt.arg0, work_buffer, to_write);
        send_command(0x59414B4F, pkt.arg1, pkt.arg0, NULL, 0);
        total_sent += to_write;

        printf("\rFlashing in progress ... %d/100%%", (int)(((float)total_sent / (1024 * 1024 * 1024) / 2) * 100 / (file_size / (1024 * 1024 * 1024))) > 100 ? 100 : (int)(((float)total_sent / (1024 * 1024 * 1024) / 2) * 100 / (file_size / (1024 * 1024 * 1024))));
        fflush(stdout);

    }
    
    free(work_buffer);
    fclose(fp);
    return 0;
}

    

int connect_device_read_info() {
    if (send_command(0x4E584E43, 0x01000001, 1024 * 1024, "host::\x0", 7)) {
        fprintf(stderr, "Failed to send command.\n");
        return 1;
    }

    char buf[512];
    int buf_len;
    adb_usb_packet pkt;
    int try_count = 10;

    while (try_count > 0) {
        if (recv_packet(&pkt, buf, &buf_len)) {
            fprintf(stderr, "Failed to receive packet.\n");
            return 1;
        }
        if (pkt.cmd == 0x4E584E43) break;
        try_count--;
    }

    if (try_count == 0) {
        fprintf(stderr, "Device doesn't send correct response\n");
        return 1;
    }

    buf[buf_len] = 0;
    if (memcmp(buf, "sideload::", 10)) {
        fprintf(stderr, "Received unexpected response: %s\n", buf);
        return 1;
    }

    return 0;
}


char* select_rom_and_generate_md5() {
    char input[256];
    while (printf("\nEnter ROM.zip path: ") && fgets(input, sizeof(input), stdin)) {
        input[strcspn(input, "\n")] = 0;
        if (strlen(input) > 4 && strcmp(input + strlen(input) - 4, ".zip") == 0 && access(input, F_OK) == 0) {
            FILE *fp = fopen(input, "r");
            if (!fp) {
                printf("\nFailed to open file!\n");
                continue;
            }

            uint8_t hash[16];
            printf("\nCalculating MD5 hash...\nthe time may vary depending on the file size (up to 2 minutes for large .zip files)...\n\nplease wait ...\n");
            md5File(fp, hash);
            fclose(fp);

            char *hash_str = malloc(33);
            char *ptr = hash_str;
            for (int i = 0; i < 16; i++) {
                ptr += sprintf(ptr, "%02x", hash[i]);
            }

            size_t result_len = strlen(input) + 34; 
            char *result = malloc(result_len);
            snprintf(result, result_len, "%s %s", input, hash_str);

            free(hash_str);
            return result;
        }
        printf("\n%s\n", strlen(input) > 0 ? "File does not exist or is not a .zip file!" : "Invalid path!");
    }
    return NULL;
}


int main() {

    #ifdef _WIN32
        if (scan_for_device() != 0) {
            printf("\n\nNo device found\n\n");
            goto out;
        }
    #else
        if (strcmp(getenv("HOME"), "/data/data/com.termux/files/home") == 0) {
            if (connect_usb_device() == 1) {
                printf("\nNo device found (termux-api)\n\n");
                goto out;
            }
        } else {
            if (scan_for_device() != 0) {
                printf("\n\nNo device found\n\n");
                goto out;
            }
        }
    #endif

    if(connect_device_read_info()) {
        printf("\nFailed to connect with device\n");
        goto out;
    }
  
    FILE *file = fopen("choi.tmp", "r");
    char choice[256] = {0};
    fgets(choice, sizeof(choice), file);
    fclose(file);

    printf("\n==========================\n");

    if (strcmp(choice, "1") == 0) {
        char *commands[] = { "getdevice:", "getversion:", "getsn:", "getcodebase:", "getbranch:", "getlanguage:", "getregion:", "getromzone:" };
        for (int i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) { printf("\n%s %s\n\n", commands[i] + 3, send_recovery_commands(commands[i])); }
        goto out;
    }

    if (strcmp(choice, "2") == 0) {
        char md5[33];
        printf("\nPlease enter the MD5 string: ");
        scanf("%32s", md5);
        generate_firmware_sign(md5);
        goto out;
    }

    if (strcmp(choice, "3") == 0) {
        char *rom_and_hash = select_rom_and_generate_md5();
        if (!rom_and_hash) return 1;
        char *path = strtok(rom_and_hash, " ");
        char *md5 = strtok(NULL, " ");
        if (!path || !md5) return 1;
        printf("path %s", path);
        printf("md5 %s", md5);
        const char *validate = generate_firmware_sign(md5);
        if (!validate) return 1;
        start_sideload(path, validate);
        goto out;
    }

    if (strcmp(choice, "4") == 0) {
        char *format= send_recovery_commands("format-data:");
        printf("\n%s\n", format);
        char *reboot= send_recovery_commands("reboot:");
        printf("\n%s\n", reboot);
        goto out;
    }

    if (strcmp(choice, "5") == 0) {
        char *reboot= send_recovery_commands("reboot:");
        printf("\n%s\n", reboot);
        goto out;
    }

out:
    remove("choi.tmp");
}





