#include <dirent.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <sys/statfs.h>
#include <sys/epoll.h>
#include <time.h>
#include <libgen.h>


#define BACK_LOG 5
#define MAX_SIZE_TO_ENCRYPT 1048576
#define SOCK_PATH "/usr/antivirus/socket"
#define KB 1024
#define FTYPE 16914836
#define DATA_STRING 128

#define RWX_EVERYONE 0777
#define R_EVERYONE 0444

int interpretInput(char *command, char *output);

int sendLogs();

int sendBackupInfo();

int scanFileHandler(char *filepath);

int scanDirHandler(char *dirname, int *malwareCount, int *fileCount);

char *extractParamFromCommand(char *command, int index);

int decrypt(char *path);

int encrypt(char *path);

int addFHash(char *filepath);

int addHashes(char *filepath);

int makeBackup(char *filepath);

int restoreBackup(char *filepath);

int s, s2;
char *hashes;

int main(void) {
    socklen_t len;
    unsigned int t;
    struct sockaddr_un local, remote;
    char command[PATH_MAX];
    char output[PATH_MAX];


    FILE *hashesFile;
    hashesFile = fopen("/usr/antivirus/hashes", "rb");
    if (hashesFile == NULL) {
        printf("Hashes file can't be opened.\n");
        return -1;
    }
    fseek(hashesFile, 0L, SEEK_END);
    size_t fsize = (size_t) ftell(hashesFile);
    fseek(hashesFile, 0L, SEEK_SET);
    hashes = malloc(fsize);
    if (hashes == NULL) {
        printf("malloc failed\n");
        return -1;
    }
    fread(hashes, sizeof(char), fsize, hashesFile);

    if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        free(hashes);
        return -1;
    }

    local.sun_family = AF_UNIX;
    strncpy(local.sun_path, SOCK_PATH, sizeof(local.sun_path));
    unlink(local.sun_path);
    len = (socklen_t) (strlen(local.sun_path) + sizeof(local.sun_family));
    if (bind(s, (struct sockaddr *) &local, len) == -1) {
        perror("bind");
        free(hashes);
        return -1;
    }
    chmod("/usr/antivirus/socket", RWX_EVERYONE);

    if (listen(s, BACK_LOG) == -1) {
        perror("listen");
        free(hashes);
        return -1;
    }

    int fd = epoll_create(0);
    struct epoll_event event;
    event.events = EPOLLIN;
    epoll_ctl(fd, EPOLL_CTL_ADD, s2, &event);
    epoll_ctl(fd, EPOLL_CTL_ADD, s, &event);

    for (;;) {
        ssize_t done, n = 0;
        printf("Waiting for a connection...\n");
        t = sizeof(remote);
        if ((s2 = accept(s, (struct sockaddr *) &remote, &t)) == -1) {
            perror("accept");
            free(hashes);
            break;
        }
        printf("Connected.\n");

        done = 0;
        do {
            memset(command, 0, PATH_MAX);
            if (epoll_wait(fd, &event, 1, -1)) {
                n = recv(s2, command, PATH_MAX, 0);                                                 // /
            }
            if (n <= 0) {
                if (n < 0) perror("recv");
                done = 1;
            }

            if (!done) {
                if (interpretInput(command, output) == -1) {
                    free(hashes);
                    return 0;
                }
                if (send(s2, output, strlen(output), 0) < 0) {
                    perror("send");
                    done = 1;
                }
            }
            memset(output, 0, PATH_MAX);
        } while (!done);
        close(s2);
        printf("Client unconnected.\n");
    }
    free(hashes);
    return 0;
}


/// \param command - input from user
/// \param output - feedback massage
/// \return 0
int interpretInput(char *command, char *output) {
    int malwareCount = 0;
    int fileCount = 0;
    char *ptr;
    if (memcmp(command, "scan-file ", sizeof("scan-file ") - 1) == 0) {
        printf("- Scan file request: %s\n", command);
        ptr = extractParamFromCommand(command, 1);
        switch (scanFileHandler(ptr)) {
            case -1:
                strncpy(output, "can't be opened", sizeof("can't be opened"));
                break;
            case 0:
                strncpy(output, "file is not a malware", sizeof("file is not a malware"));
                break;
            case 1:
                strncpy(output, "file is a malware", sizeof("file is a malware"));
                break;
            default:
                break;
        }
    } else if (memcmp(command, "scan-dir ", sizeof("scan-dir ") - 1) == 0) {
        printf("- Scan dir request: %s\n", command);
        ptr = extractParamFromCommand(command, 1);
        if (scanDirHandler(ptr, &malwareCount, &fileCount) == -1) {
            strncpy(output, "fail when try opened dir", sizeof("fail when try opened dir"));
        } else if (malwareCount == 0)
            strncpy(output, "dir is clear", sizeof("dir is clear") - 1);
        else
            snprintf(output, PATH_MAX, "in dir is malware\n   scanned: %d\n   malware: %d", fileCount, malwareCount);
    } else if (memcmp(command, "get-logs", sizeof("get-logs") - 1) == 0) {
        printf("- Logs request: %s\n", command);
        if (sendLogs() == 0)
            strncpy(output, "null", sizeof("null"));
    } else if (memcmp(command, "decrypt-file ", sizeof("decrypt-file ") - 1) == 0) {
        ptr = extractParamFromCommand(command, 1);
        if (decrypt(ptr) == 1) {
            strncpy(output, "Decrypted successful", sizeof("Decrypted successful"));
        } else {
            strncpy(output, "Decrypted failed", sizeof("Decrypted failed"));
        }
    } else if (memcmp(command, "stop", sizeof("stop") - 1) == 0) {
        printf("- Stop request: %s\n", command);
        return -1;
    } else if ((memcmp(command, "add-fhash ", sizeof("add-fhash ") - 1) == 0)) {
        ptr = extractParamFromCommand(command, 1);
        if (addFHash(ptr) == 0)
            strncpy(output, "hash added successful", sizeof("hash added successful"));
        else
            strncpy(output, "hash not added", sizeof("hash not added"));
    } else if ((memcmp(command, "add-hashes ", sizeof("add-hashes ") - 1) == 0)) {
        ptr = extractParamFromCommand(command, 1);
        if (addHashes(ptr) == 0)
            strncpy(output, "hashes added successful", sizeof("hashes added successful"));
        else
            strncpy(output, "hashes not added", sizeof("hashes not added"));
    } else if ((memcmp(command, "make-backup ", sizeof("make-backup ") - 1) == 0)) {
        ptr = extractParamFromCommand(command, 1);
        if (makeBackup(ptr) == 0)
            strncpy(output, "backup successful", sizeof("backup successful"));
        else
            strncpy(output, "backup not successful", sizeof("backup not successful"));
    } else if ((memcmp(command, "restore-backup ", sizeof("restore-backup ") - 1) == 0)) {
        ptr = extractParamFromCommand(command, 1);
        if (restoreBackup(ptr) == 0)
            strncpy(output, "restore successful", sizeof("restore successful"));
        else
            strncpy(output, "restore not successful", sizeof("restore not successful"));
    } else if ((memcmp(command, "get-backup-info", sizeof("get-backup-info") - 1) == 0)) {
        if (sendBackupInfo() == 0)
            strncpy(output, "null", sizeof("null") - 1);
    } else {
        printf("- Invalid request: %s\n", command);
        strncpy(output, "invalid input", sizeof("invalid input") - 1);
    }
    return 0;
}


/// \param command - input from user
/// \param index - string index
/// \return pointer to n-string separated by " "
char *extractParamFromCommand(char *command, int index) {
    const char delimiter[] = " ";
    char *ptr;
    ptr = strtok(command, delimiter);
    for (int i = 0; i < index; i++) {
        ptr = strtok(NULL, delimiter);
    }
    ptr[strlen(ptr) - 1] = '\0';
    return ptr;
}


int sendLogs() {
    FILE *file1;
    int n = 0;
    char buff[PATH_MAX];
    file1 = fopen("/usr/antivirus/logs.txt", "rb");
    if (file1 == NULL) {
        printf("logs can't be opened.\n");
        return -1;
    }
    memset(buff, 0, sizeof(buff));
    while (fread(buff, 1, PATH_MAX, file1) != 0) {
        n = 1;
        send(s2, buff, sizeof(buff), 0);
        memset(buff, 0, sizeof(buff));
    }
    fclose(file1);
    return n;
}

int sendBackupInfo() {
    FILE *file1;
    int n = 0;
    char buff[PATH_MAX];
    file1 = fopen("/usr/antivirus/backup/info", "rb");
    if (file1 == NULL) {
        printf("info can't be opened.\n");
        return -1;
    }
    memset(buff, 0, sizeof(buff));
    while (fread(buff, 1, PATH_MAX, file1) != 0) {
        n = 1;
        send(s2, buff, sizeof(buff), 0);
        memset(buff, 0, sizeof(buff));
    }
    fclose(file1);
    return n;
}


/// \param filepath <path to file>"
/// \return
/// -1 when file not found,
/// 0 when file is not a malware,
/// 1 when file is a malware
int scanFileHandler(char *filepath) {
    FILE *file1;
    FILE *file2;
    MD5_CTX mdContext;
    unsigned char fileHash[MD5_DIGEST_LENGTH];
    char filepathCopy[PATH_MAX];
    char pathToQuarantine[PATH_MAX] = "/usr/antivirus/quarantine/";
    unsigned long bytes;
    char *ptr;
    char delimiter[] = "/";
    size_t md5chunkSize = 1024;
    unsigned char data[md5chunkSize];

    struct statfs sfs;

    if (statfs(filepath, &sfs) == -1)
        return -1;
    int randomfile = FTYPE;
    if (sfs.f_type == randomfile)
        return -1;

    //compute hash
    file1 = fopen(filepath, "rb");
    if (file1 == NULL) {
        printf("%s can't be opened.\n", filepath);
        return -1;
    }

    MD5_Init(&mdContext);
    while ((bytes = fread(data, 1, md5chunkSize, file1)) != 0) {
        MD5_Update(&mdContext, data, bytes);
    }
    MD5_Final(fileHash, &mdContext);
    fclose(file1);

    //prepare logs (file1)
    file1 = fopen("/usr/antivirus/logs.txt", "a");
    if (file1 == NULL) {
        printf("Logs file can't be opened.\n");
        return -1;
    }
    chmod("/usr/antivirus/logs.txt", R_EVERYONE);


    char *hashesPtr = hashes;
    for (;;) {
        if (hashesPtr > hashes + strlen(hashes))
            break;
        if (memcmp(hashesPtr, fileHash, MD5_DIGEST_LENGTH) == 0) {
            fprintf(file1, "%s - %s\n", filepath, "is a malware");
            fclose(file1);

            //create name in quarantine
            strncpy(filepathCopy, filepath, PATH_MAX);
            ptr = strtok(filepathCopy, delimiter);
            while (ptr != NULL) {
                strncat(pathToQuarantine, "_", sizeof("_"));
                strncat(pathToQuarantine, ptr, strlen(ptr));
                ptr = strtok(NULL, delimiter);
            }

            //move file to quarantine
            //file1 - src; file2 - dst
            file1 = fopen(filepath, "rb");
            file2 = fopen(pathToQuarantine, "wb");
            if (file1 == NULL || file2 == NULL) {
                printf("Error while copying.\n");
                return -1;
            }
            while ((bytes = fread(data, sizeof(char), sizeof(data), file1)) != 0) {
                fwrite(data, sizeof(char), bytes, file2);
                memset(data, 0, sizeof(data));
            }
            fclose(file1);
            fclose(file2);
            //remove file from current location
            remove(filepath);
            chmod(pathToQuarantine, 0000);
            encrypt(pathToQuarantine);
            return 1;
        }
        hashesPtr = hashesPtr + MD5_DIGEST_LENGTH;
    }
    fclose(file1);
    return 0;
}

///
/// \param dirname - directory to snac
/// \param malwareCount - amount of malware found
/// \param fileCount - amount of scanned files
/// \return -1 when dir not found,
int scanDirHandler(char *dirname, int *malwareCount, int *fileCount) {
    DIR *dir;
    struct dirent *dirp;
    char cwd[PATH_MAX];
    dir = opendir(dirname);
    if (dir == NULL) {
        printf("%s can't be opened.\n", dirname);
        return -1;
    }
    chdir(dirname);
    while ((dirp = readdir(dir)) != NULL) {
        getcwd(cwd, sizeof(cwd));
        strncat(cwd, "/", sizeof("/"));
        if (dirp->d_type == 4) {
            if (strcmp(dirp->d_name, ".") == 0 || strcmp(dirp->d_name, "..") == 0) { continue; }
            scanDirHandler(dirp->d_name, malwareCount, fileCount);
        } else {
            strncat(cwd, dirp->d_name, sizeof(dirp->d_name));
            if (scanFileHandler(cwd) == 1) {
                *malwareCount = *malwareCount + 1;
            }
            *fileCount = *fileCount + 1;
        }
    }
    chdir("..");
    closedir(dir);
    return 0;
}

///
/// \param path to file
/// \return  when encrypted successful, -1 error
int encrypt(char *path) {
    //Get ciphered size
    size_t pathLength = strlen(path);
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        printf("Error during encryption.\n");
        return -1;
    }
    fseek(file, 0L, SEEK_END);
    size_t fsize = (size_t) ftell(file);
    if (fsize > MAX_SIZE_TO_ENCRYPT) {
        fclose(file);
        return -1;
    }
    fseek(file, 0L, SEEK_SET);
    strncat(path, "_ciphered", sizeof("_ciphered"));
    FILE *ciphered = fopen(path, "wb");
    if (ciphered == NULL) {
        printf("Error during encryption.\n");
        return -1;
    }

    //set back to normal
    int outLen1 = 0;
    int outLen2 = 0;
    unsigned char *indata;
    indata = malloc(fsize);
    if (indata == NULL) {
        printf("malloc failed\n");
        return -1;
    }
    unsigned char *outdata;
    outdata = malloc(fsize * 2);
    if (outdata == NULL) {
        printf("malloc failed\n");
        free(indata);
        return -1;
    }
    unsigned char ckey[] = "hasloNieDoZlamania";
    unsigned char ivec[] = "najlepszyAntyvirus123";

    //Read File
    fread(indata, sizeof(char), fsize, file);//Read Entire File

    //Set up encryption
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(ctx, EVP_aes_128_cbc(), ckey, ivec);
    EVP_EncryptUpdate(ctx, outdata, &outLen1, indata, (int) fsize);
    EVP_EncryptFinal(ctx, outdata + outLen1, &outLen2);
    fwrite(outdata, sizeof(char), outLen1 + outLen2, ciphered);
    EVP_CIPHER_CTX_free(ctx);
    CRYPTO_cleanup_all_ex_data();
    EVP_cleanup();

    fclose(ciphered);
    fclose(file);

    free(indata);
    free(outdata);

    chmod(path, 0000);
    //remove file
    path = path + pathLength;
    memset(path, 0, sizeof("_ciphered") - 1);
    path = path - pathLength;
    remove(path);
    return 1;
}

///
/// \param path to file
/// \return 1 when decrypted successful, -1 error
int decrypt(char *path) {
    FILE *ciphered = fopen(path, "rb");
    if (ciphered == NULL) {
        printf("Error during decryption\n");
        return -1;
    }
    //Get ciphered size
    fseek(ciphered, 0L, SEEK_END);
    size_t fsize = (size_t) ftell(ciphered);
    if (fsize > 2 * MAX_SIZE_TO_ENCRYPT) {
        printf("Error during decryption\n");
        fclose(ciphered);
        return -1;
    }

    //set back to normal
    fseek(ciphered, 0L, SEEK_SET);
    //remove file
    strncat(path, "_decipher", sizeof("_decipher"));
    FILE *file = fopen(path, "wb");
    if (file == NULL) {
        printf("Error during decryption\n");
        return -1;
    }

    int outLen1 = 0;
    int outLen2 = 0;
    unsigned char *indata;
    indata = malloc(fsize);
    if (indata == NULL) {
        printf("malloc failed\n");
        return -1;
    }
    unsigned char *outdata;
    outdata = malloc(fsize);
    if (outdata == NULL) {
        printf("malloc failed\n");
        free(indata);
        return -1;
    }
    unsigned char ckey[] = "hasloNieDoZlamania";
    unsigned char ivec[] = "najlepszyAntyvirus123";

    //Read File
    fread(indata, sizeof(char), fsize, ciphered);//Read Entire File

    //setup decryption
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit(ctx, EVP_aes_128_cbc(), ckey, ivec);
    EVP_DecryptUpdate(ctx, outdata, &outLen1, indata, (int) fsize);
    EVP_DecryptFinal(ctx, outdata + outLen1, &outLen2);
    fwrite(outdata, sizeof(char), outLen1 + outLen2, file);
    EVP_CIPHER_CTX_free(ctx);
    CRYPTO_cleanup_all_ex_data();
    EVP_cleanup();

    fclose(ciphered);
    fclose(file);

    free(indata);
    free(outdata);
    return 1;
}

int addFHash(char *filepath) {
    FILE *file1;
    MD5_CTX mdContext;
    unsigned char fileHash[MD5_DIGEST_LENGTH];
    size_t md5chunkSize = 1024;
    unsigned char data[md5chunkSize];
    unsigned long bytes;


    file1 = fopen(filepath, "rb");
    if (file1 == NULL) {
        printf("%s can't be opened.\n", filepath);
        return -1;
    }
    MD5_Init(&mdContext);
    while ((bytes = fread(data, 1, md5chunkSize, file1)) != 0) {
        MD5_Update(&mdContext, data, bytes);
    }
    MD5_Final(fileHash, &mdContext);
    fclose(file1);

    file1 = fopen("/usr/antivirus/hashes", "ab");
    if (file1 == NULL) {
        printf("%s can't be opened.\n", filepath);
        return -1;
    }

    fwrite(fileHash, MD5_DIGEST_LENGTH, 1, file1);
    fclose(file1);

    free(hashes);


    file1 = fopen("/usr/antivirus/hashes", "rb");
    if (file1 == NULL) {
        printf("Hashes file can't be opened.\n");
        return -1;
    }
    fseek(file1, 0L, SEEK_END);
    size_t fsize = (size_t) ftell(file1);
    fseek(file1, 0L, SEEK_SET);
    hashes = malloc(fsize);
    if (hashes == NULL) {
        printf("malloc failed\n");
        return -1;
    }
    fread(hashes, sizeof(char), fsize, file1);
    return 0;
}

int addHashes(char *filepath) {
    FILE *file1;
    FILE *file2;
    char hash[MD5_DIGEST_LENGTH];
    file1 = fopen(filepath, "rb");
    if (file1 == NULL) {
        printf("Hashes file can't be opened.\n");
        return -1;
    }
    fseek(file1, 0L, SEEK_END);
    size_t fsize = (size_t) ftell(file1);
    fseek(file1, 0L, SEEK_SET);
    size_t newHashesSize = strlen(hashes) + fsize;
    free(hashes);
    hashes = malloc(newHashesSize);

    file2 = fopen("/usr/antivirus/hashes", "ab");
    if (file2 == NULL) {
        printf("%s can't be opened.\n", filepath);
        return -1;
    }

    while (fread(hash, MD5_DIGEST_LENGTH, 1, file1) != 0) {
        fwrite(hash, MD5_DIGEST_LENGTH, 1, file2);
    }
    fclose(file1);
    fclose(file2);

    file2 = fopen("/usr/antivirus/hashes", "rb");
    if (file2 == NULL) {
        printf("%s can't be opened.\n", filepath);
        return -1;
    }
    fread(hashes, sizeof(char), newHashesSize, file2);
    fclose(file2);
    return 0;
}


int makeBackup(char *filepath) {
    FILE *file1;
    FILE *file2;
    char *ptr;
    char filepathCopy[PATH_MAX];
    char backupFilepath[PATH_MAX] = "/usr/antivirus/backup/";
    unsigned long bytes;
    unsigned char data[KB];


    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    char date[DATA_STRING];
    snprintf(date, DATA_STRING, "%d-%02d-%02d-:%02d:%02d:%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec);

    strncpy(filepathCopy, filepath, PATH_MAX);

    strncat(backupFilepath, date, sizeof(backupFilepath) - strlen(backupFilepath) - 1);

    ptr = basename(filepath);
    strncat(backupFilepath, "_", sizeof("_"));
    strncat(backupFilepath, ptr, strlen(ptr));


    file1 = fopen(filepath, "rb");
    file2 = fopen(backupFilepath, "wb+");
    if (file1 == NULL || file2 == NULL) {
        printf("Error while copying.\n");
        return -1;
    }

    while ((bytes = fread(data, sizeof(char), sizeof(data), file1)) != 0) {
        fwrite(data, sizeof(char), bytes, file2);
        memset(data, 0, sizeof(data));
    }
    fclose(file1);
    fclose(file2);

    file1 = fopen("/usr/antivirus/backup/info", "ab+");
    if (file1 == NULL) {
        printf("Logs file can't be opened.\n");
        return -1;
    }

    ptr = backupFilepath;
    ptr = ptr + sizeof("/usr/antivirus/backup/") - 1;
    fwrite(ptr, strlen(backupFilepath) - (sizeof("/usr/antivirus/backup/") - 1), 1, file1);
    fwrite(";", 1, 1, file1);
    fwrite(filepath, strlen(filepath), 1, file1);
    fwrite("\n", 1, 1, file1);
    fclose(file1);
    return 0;
}


int restoreBackup(char *filepath) {
    FILE *file1;
    FILE *file2;
    char *ptr;
    char delimiter1[] = ";";
    char dst[PATH_MAX];
    char src[PATH_MAX] = "/usr/antivirus/backup/";
    char line[PATH_MAX];

    unsigned long bytes;
    unsigned char data[KB];

    file1 = fopen("/usr/antivirus/backup/info", "r");
    if (file1 == NULL) {
        printf("Info file can't be opened.\n");
        return -1;
    }


    while (fgets(line, PATH_MAX, file1) != 0) {
        if (memcmp(line, filepath, strlen(filepath)) == 0) {
            break;
        }
    }

    ptr = line;
    strtok(ptr, delimiter1);
    ptr = strtok(NULL, delimiter1);
    strncpy(dst, ptr, strlen(ptr) - 1);
    fclose(file1);

    strncat(src, filepath, strlen(filepath));
    file1 = fopen(src, "rb");
    file2 = fopen(dst, "wb");
    if (file1 == NULL || file2 == NULL) {
        printf("Error while copying.\n");
        return -1;
    }
    while ((bytes = fread(data, sizeof(char), sizeof(data), file1)) != 0) {
        fwrite(data, sizeof(char), bytes, file2);
        memset(data, 0, sizeof(data));
    }
    fclose(file1);
    fclose(file2);

    return 0;
}