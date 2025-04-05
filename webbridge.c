#define _CRT_SECURE_NO_WARNINGS  // Disables POSIX deprecation warnings
#pragma warning(disable:4996)   // Disable C4996

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <locale.h>
#include <errno.h>
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <io.h>
#include <direct.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <dirent.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef _WIN32
#pragma comment(lib, "Ws2_32.lib")
#define snprintf _snprintf
#endif

#define socklen_t int
#define DEFAULT_PORT 8080
#define CHUNK_SIZE 8192
#define TIMEOUT 10

#ifdef _WIN32
#define strncasecmp _strnicmp
#endif

#ifdef _WIN32
#ifdef _MSC_VER
typedef int ssize_t;  // Define ssize_t for Windows
#endif
#define snprintf _snprintf
#define PATH_SEPARATOR '\\'
#define mkdir(path, mode) _mkdir(path)  // _mkdir doesn't take mode
#define O_BINARY _O_BINARY
#define close_socket(s) closesocket(s)
#define socklen_t int
#ifndef S_ISDIR
#define S_ISDIR(m)  (((m) & _S_IFDIR) == _S_IFDIR)
#endif
#else
#define PATH_SEPARATOR '/'
#define O_BINARY 0
#define close_socket(s) close(s)
#endif

#ifdef _WIN32
#define PATH_SEPARATOR '\\'
#define PATH_SEPARATOR_STR "\\"
#else
#define PATH_SEPARATOR '/'
#define PATH_SEPARATOR_STR "/"
#endif


typedef struct {
    char method[16];
    char path[256];
    char protocol[16];
    char headers[2048];
    char *body;
    size_t body_length;
    int content_length;
} HttpRequest;

typedef struct {
    char name[256];
    int is_directory;
    char size_str[64];
    char time_str[64];
} FileEntry;

char base_directory[256] = ".";
int server_port = DEFAULT_PORT;
char text_filename[256] = "";
char *text_file_content = NULL;

// Constants for HTML parts
const char *HTML_HEADER = "<!DOCTYPE html>"
"<html><head>"
"<meta charset=\"UTF-8\">"
"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
"<title>webbridge</title>";

const char *HTML_STYLES = "<style>"
"body { font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; overflow-x: hidden; }"
"header { background-color: lightblue; color: black; padding: 20px 10px; text-align: center; }"
"header h1 { margin: 0; font-size: 36px; }"
".container { padding: 20px; max-width: 100%; box-sizing: border-box; }"
"h2 { color: #333; font-size: 24px; margin-bottom: 10px; }"
"form { margin-bottom: 15px; padding: 15px; background-color: #fff; border-radius: 5px; }"
"input[type=file], textarea, input[type=text] { padding: 10px; width: 100%; font-size: 16px; margin-bottom: 10px; box-sizing: border-box; }"
"input[type=submit], button { padding: 10px 20px; background-color: lightblue; width: 100%; color: black; border: none; cursor: pointer; font-size: 16px; border-radius: 5px; }"
"input[type=submit]:hover, button:hover { background-color: lightblue; }"
"table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }"
"th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; font-size: 18px; }"
"th { background-color: #f2f2f2; }"
"tr:nth-child(even) { background-color: #eaf5ff; }"
"tr:nth-child(odd) { background-color: whitesmoke; }"
"tr:hover { background-color: #f1f1f1; }"
"a { text-decoration: none; color: #333; }"
"a:hover { text-decoration: underline; }"
".directory { font-weight: bold; }"
".modal { display: none; position: fixed; z-index: 1; left: 0; top: 0;"
" width: 100%; height: 100%; overflow: auto; background-color: rgba(0,0,0,0.4); }"
".modal-content { background-color: #fefefe; margin: 15% auto; padding: 20px;"
" border: 1px solid #888; width: 80%; max-width: 400px; border-radius: 5px; }"
".close { color: #aaa; float: right; font-size: 28px; font-weight: bold; }"
".close:hover, .close:focus { color: black; text-decoration: none; cursor: pointer; }"
"footer { background-color: lightblue; color: black; text-align: center; padding: 15px; width: 100%; }"
"footer p { margin: 5px 0; font-size: 14px; }"
"@media screen and (max-width: 600px) and (orientation: portrait) {"
"  header h1 { font-size: 28px; }"
"  h2 { font-size: 20px; }"
"  th, td { font-size: 16px; padding: 10px; }"
"  input[type=submit], button { width: 100%; font-size: 18px; }"
"  th:nth-child(3), td:nth-child(3) { display: none; }"
"}"
"@media screen and (min-width: 601px), (orientation: landscape) {"
"  header h1 { font-size: 24px; }"
"  h2 { font-size: 18px; }"
"  th, td { font-size: 14px; padding: 8px; }"
"  input[type=submit], button { font-size: 14px; }"
"}"
"</style>";

const char *HTML_SCRIPTS = "<script>"
"function validateUploadForm() {"
"  var fileInput = document.querySelector('input[type=\"file\"]');"
"  if (fileInput.files.length === 0) {"
"    alert('Please select at least one file to upload.');"
"    return false;"
"  }"
"  return true;"
"}"
"function validateFolderForm() {"
"  var folderName = document.getElementById('folderName').value;"
"  if (folderName.trim() === '') {"
"    alert('Please enter a folder name.');"
"    return false;"
"  }"
"  return true;"
"}"
"</script>";

const char *HTML_BODY_START = "</head><body>"
"<header><h1>webbridge</h1></header>"
"<div class=\"container\">";

const char *HTML_BODY_END = "</div>"
"<footer>"
"<p>Powered by <strong>webbridge</strong> &ndash; A simple web-based file manager.</p>"
"<p>Visit the <a href=\"https://github.com/Delphi-Coder/Web-bridge\" target=\"_blank\" style=\"color: green; text-decoration: underline;\">project page</a> for more info.</p>"
"</footer>"
"<script>"
"var modal = document.getElementById('newFolderModal');"
"window.onclick = function(event) {"
"  if (event.target == modal) {"
"    modal.style.display = 'none';"
"  }"
"}"
"</script>"
"</body></html>";
/* HTTP Response */

void send_response(int client_socket, const char *status, const char *content_type, const char *body) {
    char response[16384];
    int content_length = (int)strlen(body);
    int response_length = snprintf(response, sizeof(response),
                                   "HTTP/1.1 %s\r\n"
                                   "Content-Type: %s\r\n"
                                   "Content-Length: %d\r\n"
                                   "Connection: close\r\n"
                                   "\r\n"
                                   "%s",
                                   status, content_type, content_length, body);

    send(client_socket, response, response_length, 0);
}

int hex_to_int(char c) {
    c = tolower((unsigned char)c);
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return 0;
}

void url_decode(char *src, char *dest) {
    char *pstr = src, *pbuf = dest;
    while (*pstr) {
        if (*pstr == '%') {
            if (pstr[1] && pstr[2]) {
                *pbuf++ = (char)((hex_to_int(pstr[1]) << 4) | hex_to_int(pstr[2]));
                pstr += 2;
            }
        } else if (*pstr == '+') {
            *pbuf++ = ' ';
        } else {
            *pbuf++ = *pstr;
        }
        pstr++;
    }
    *pbuf = '\0';
}

void *memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen) {
    const unsigned char *haystack_ptr;
    const unsigned char *needle_ptr;
    size_t i;

    if (needlelen == 0) return (void *)haystack;
    if (haystacklen < needlelen) return NULL;

    haystack_ptr = (const unsigned char *)haystack;
    needle_ptr = (const unsigned char *)needle;

    for (i = 0; i <= haystacklen - needlelen; i++) {
        if (memcmp(haystack_ptr + i, needle_ptr, needlelen) == 0) {
            return (void *)(haystack_ptr + i);
        }
    }
    return NULL;
}

int get_header_value(const char *headers, const char *key, char *value, size_t value_size) {
    const char *key_start = headers;
    size_t key_len = strlen(key);
    size_t value_len;  // Declare value_len at the top

    while (key_start && *key_start) {
        // Find the end of the current line
        const char *line_end = strstr(key_start, "\r\n");
        if (!line_end) {
            line_end = headers + strlen(headers);
        }

        // Check if the current line starts with the key
        if (strncasecmp(key_start, key, key_len) == 0 && key_start[key_len] == ':') {
            // Extract the value
            const char *value_start = key_start + key_len + 1; // Skip key and ':'
            while (*value_start == ' ') value_start++; // Skip spaces
            value_len = line_end - value_start;
            if (value_len >= value_size) {
                value_len = value_size - 1;
            }
            strncpy(value, value_start, value_len);
            value[value_len] = '\0';
            return 0; // Found
        }

        // Move to the next line
        if (*line_end == '\0') {
            break;
        }
        key_start = line_end + 2; // Skip "\r\n"
    }

    return -1; // Not found
}

void mkdir_recursive(const char *dir) {
    char tmp[1024];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", dir);
    len = strlen(tmp);
    if (tmp[len - 1] == PATH_SEPARATOR) tmp[len - 1] = '\0';

    for (p = tmp + 1; *p; p++) {
        if (*p == PATH_SEPARATOR) {
            *p = '\0';
            #ifdef _WIN32
            _mkdir(tmp);
            #else
            mkdir(tmp, S_IRWXU);
            #endif
            *p = PATH_SEPARATOR;
        }
    }
    #ifdef _WIN32
    _mkdir(tmp);
    #else
    mkdir(tmp, S_IRWXU);
    #endif
}

void extract_filename(char *header, char *filename) {
    char *pos = strstr(header, "filename=");
    if (pos) {
        pos += 9;  // Skip 'filename='
        if (*pos == '"' || *pos == '\'') {
            char quote = *pos++;
            char *end = strchr(pos, quote);
            if (end) {
                *end = '\0';
            }
            strncpy(filename, pos, 255);
            filename[255] = '\0';
        } else {
            char *end = strpbrk(pos, ";\r\n");
            if (end) {
                *end = '\0';
            }
            strncpy(filename, pos, 255);
            filename[255] = '\0';
        }
    } else {
        strcpy(filename, "uploaded_file");
    }
}

void send_redirect(int client_socket, const char *location) {
    char response[1024];
    snprintf(response, sizeof(response),
             "HTTP/1.1 303 See Other\r\n"
             "Location: %s\r\n"
             "Connection: close\r\n\r\n", location);
    send(client_socket, response, (int)strlen(response), 0);
}

void format_time(time_t mod_time, char *time_str, size_t time_str_size) {
    struct tm *tm_info;
    tm_info = localtime(&mod_time);
    strftime(time_str, time_str_size, "%Y-%m-%d %H:%M:%S", tm_info);
}

void urlencode(const char *src, char *dest, size_t dest_size) {
    const char *hex = "0123456789ABCDEF";
    size_t i = 0;
    while (*src && i < dest_size - 1) {
        if (isalnum((unsigned char)*src) || *src == '-' || *src == '_' || *src == '.' || *src == '~' || *src == '/') {
            dest[i++] = *src;
        } else {
            if (i + 3 >= dest_size) break;
            dest[i++] = '%';
            dest[i++] = hex[((unsigned char)*src >> 4) & 0xF];
            dest[i++] = hex[(unsigned char)*src & 0xF];
        }
        src++;
    }
    dest[i] = '\0';
}

void format_file_size(off_t size, char *size_str, size_t size_str_size) {
    if (size < 1024) {
        snprintf(size_str, size_str_size, "%ld bytes", (long)size);
    } else if (size < 1024 * 1024) {
        snprintf(size_str, size_str_size, "%.2f KB", size / 1024.0);
    } else if (size < 1024 * 1024 * 1024) {
        snprintf(size_str, size_str_size, "%.2f MB", size / (1024.0 * 1024.0));
    } else {
        snprintf(size_str, size_str_size, "%.2f GB", size / (1024.0 * 1024.0 * 1024.0));
    }
}

void sanitize_path(char *path) {
    char sanitized[1024] = "";
    char *token;
    char *rest = path;

#ifdef _WIN32
    // On Windows, split on both '/' and '\'
    while ((token = strtok(rest, "/\\")) != NULL) {
#else
    // On Linux/Unix, split only on '/'
    while ((token = strtok(rest, "/")) != NULL) {
#endif
        rest = NULL;
        if (strcmp(token, "..") == 0 || strcmp(token, ".") == 0) continue; // Skip parent and current directory references
        if (strlen(sanitized) + strlen(token) + 2 >= sizeof(sanitized)) break;

        if (strlen(sanitized) > 0) {
            // Append PATH_SEPARATOR between tokens
            strcat(sanitized, PATH_SEPARATOR_STR);
        }
        strcat(sanitized, token);
    }

    // Do not add a leading path separator
    strcpy(path, sanitized);
}

void join_paths(const char *path1, const char *path2, char *result, size_t result_size) {
    size_t len1 = strlen(path1);
    size_t len2 = strlen(path2);
    int need_sep = 0;
    result[0] = '\0';

    /* Copy path1 to result */
    if (len1 > 0) {
        strncpy(result, path1, result_size - 1);
        result[result_size - 1] = '\0';
    }

    /* Determine if we need to add a separator */
    if (len1 > 0 && len2 > 0) {
        if (path1[len1 - 1] != '/' && path1[len1 - 1] != '\\' && path2[0] != '/' && path2[0] != '\\') {
            need_sep = 1;
        } else if ((path1[len1 - 1] == '/' || path1[len1 - 1] == '\\') && (path2[0] == '/' || path2[0] == '\\')) {
            /* Skip one of the separators */
            path2++;
            len2--;
        }
    } else if (len1 == 0 && len2 > 0 && (path2[0] == '/' || path2[0] == '\\')) {
        /* If path1 is empty and path2 starts with a separator, skip it */
        path2++;
        len2--;
    }

    /* Add separator if needed */
    if (need_sep) {
        strncat(result, PATH_SEPARATOR_STR, result_size - strlen(result) - 1);
    }

    /* Append path2 to result */
    if (len2 > 0) {
        strncat(result, path2, result_size - strlen(result) - 1);
    }
}

/* Directory Listing */
int get_directory_entries(const char *directory_path, FileEntry *entries, int max_entries) {
    int count = 0;
    struct stat file_stat;
    char full_path[1024];

#ifdef _WIN32
    WIN32_FIND_DATA find_data;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    char search_path[1024];

    snprintf(search_path, sizeof(search_path), "%s\\*", directory_path);

    hFind = FindFirstFile(search_path, &find_data);
    if (hFind == INVALID_HANDLE_VALUE) {
        return -1;
    }

    do {
        if (strcmp(find_data.cFileName, ".") == 0 || strcmp(find_data.cFileName, "..") == 0) {
            continue;
        }

        snprintf(full_path, sizeof(full_path), "%s\\%s", directory_path, find_data.cFileName);

        if (stat(full_path, &file_stat) == 0) {
            strncpy(entries[count].name, find_data.cFileName, sizeof(entries[count].name) - 1);
            entries[count].name[sizeof(entries[count].name) - 1] = '\0';

            entries[count].is_directory = S_ISDIR(file_stat.st_mode);

            format_file_size(file_stat.st_size, entries[count].size_str, sizeof(entries[count].size_str));
            format_time(file_stat.st_mtime, entries[count].time_str, sizeof(entries[count].time_str));

            count++;
            if (count >= max_entries) {
                break;
            }
        }
    } while (FindNextFile(hFind, &find_data) != 0);

    FindClose(hFind);

#else
    DIR *dir;
    struct dirent *entry;

    dir = opendir(directory_path);
    if (!dir) {
        return -1;
    }

    while ((entry = readdir(dir)) != NULL && count < max_entries) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        snprintf(full_path, sizeof(full_path), "%s/%s", directory_path, entry->d_name);
        if (stat(full_path, &file_stat) == 0) {
            strncpy(entries[count].name, entry->d_name, sizeof(entries[count].name) - 1);
            entries[count].name[sizeof(entries[count].name) - 1] = '\0';

            entries[count].is_directory = S_ISDIR(file_stat.st_mode);

            format_file_size(file_stat.st_size, entries[count].size_str, sizeof(entries[count].size_str));
            format_time(file_stat.st_mtime, entries[count].time_str, sizeof(entries[count].time_str));

            count++;
        }
    }

    closedir(dir);
#endif

    return count;
}

int compare_entries(const void *a, const void *b) {
    const FileEntry *entry_a = (const FileEntry *)a;
    const FileEntry *entry_b = (const FileEntry *)b;

    // Directories come before files
    if (entry_a->is_directory && !entry_b->is_directory) {
        return -1;
    }
    if (!entry_a->is_directory && entry_b->is_directory) {
        return 1;
    }
    // Both are directories or both are files; sort alphabetically
    return strcmp(entry_a->name, entry_b->name);
}

/* Generate Directory Listing HTML */
char* generate_directory_listing_html(FileEntry *entries, int num_entries, const char *current_path,
                                      const char *status_message, const char *text_file_content) {
    size_t body_size = 8192 + (num_entries * 512);
    char *body = (char *)malloc(body_size);
    size_t offset = 0;
    int i;
    char encoded_current_path[512];
    char web_current_path[512];

    if (!body) return NULL;

    // URL-encode current_path
    urlencode(current_path, encoded_current_path, sizeof(encoded_current_path));

    // Replace backslashes with forward slashes in current_path for web display
    strncpy(web_current_path, current_path, sizeof(web_current_path) - 1);
    web_current_path[sizeof(web_current_path) - 1] = '\0';
    {
        char *p = web_current_path;
        while (*p) {
            if (*p == '\\') *p = '/';
            p++;
        }
    }

    // Sort entries: Directories first, then files
    qsort(entries, num_entries, sizeof(FileEntry), compare_entries);

    // Generate HTML content
    offset += snprintf(body + offset, body_size - offset, "%s%s%s%s",
                       HTML_HEADER, HTML_STYLES, HTML_SCRIPTS, HTML_BODY_START);

    if (status_message && strlen(status_message) > 0) {
        offset += snprintf(body + offset, body_size - offset, "<p>%s</p>", status_message);
    }

    // Display text file content if available
    if (text_file_content && strlen(text_file_content) > 0) {
        offset += snprintf(body + offset, body_size - offset, "<h2>Text Content</h2>");
        offset += snprintf(body + offset, body_size - offset, "<textarea readonly>%s</textarea><hr>", text_file_content);
    }

    // Text Submission Form
    offset += snprintf(body + offset, body_size - offset,
                       "<h2>Submit Text</h2>"
                       "<form action=\"/submit_text%s\" method=\"post\">"
                       "<textarea name=\"user_text\" rows=\"3\" placeholder=\"Enter text to submit...\"></textarea>"
                       "<input type=\"submit\" value=\"Submit Text\"></form><hr>", encoded_current_path);

    // File Upload Form
    offset += snprintf(body + offset, body_size - offset,
                       "<h2>File Upload</h2>"
                       "<form action=\"/upload%s\" method=\"post\" enctype=\"multipart/form-data\" onsubmit=\"return validateUploadForm()\">"
                       "<input type=\"file\" name=\"files[]\" multiple>"
                       "<input type=\"submit\" value=\"&#11014; Upload to %s\">"
                       "</form><hr>", encoded_current_path, web_current_path);

    // New Folder Modal
    offset += snprintf(body + offset, body_size - offset,
                       "<button onclick=\"document.getElementById('newFolderModal').style.display='block'\">&#128193; New Folder</button>"
                       "<div id=\"newFolderModal\" class=\"modal\">"
                       "<div class=\"modal-content\">"
                       "<span onclick=\"document.getElementById('newFolderModal').style.display='none'\" class=\"close\">&times;</span>"
                       "<form action=\"/create_folder%s\" method=\"post\" onsubmit=\"return validateFolderForm()\">"
                       "<h2>Create New Folder</h2>"
                       "<input type=\"text\" id=\"folderName\" name=\"folder_name\" placeholder=\"Folder Name\" required>"
                       "<input type=\"submit\" value=\"Create Folder\">"
                       "</form></div></div><hr>", encoded_current_path);

    // Directory listing
    offset += snprintf(body + offset, body_size - offset, "<h2>Files in Directory: %s</h2>", web_current_path);
    offset += snprintf(body + offset, body_size - offset, "<table><tr><th>Name</th><th>Size</th><th>Last Modified</th></tr>");

    // Parent directory link
    if (strcmp(web_current_path, "/") != 0) {
        char parent_path[512];
        char encoded_parent_path[512];
        char *last_slash;

        strncpy(parent_path, web_current_path, sizeof(parent_path) - 1);
        parent_path[sizeof(parent_path) - 1] = '\0';
        last_slash = strrchr(parent_path, '/');
        if (last_slash && last_slash != parent_path) {
            *last_slash = '\0';
        } else {
            strcpy(parent_path, "/");
        }
        urlencode(parent_path, encoded_parent_path, sizeof(encoded_parent_path));
        offset += snprintf(body + offset, body_size - offset,
                           "<tr><td><a href=\"%s\">..</a></td><td></td><td></td></tr>", encoded_parent_path);
    }

    for (i = 0; i < num_entries; i++) {
        char encoded_name[512];
        char item_path[1024];
//        char web_item_path[1024];

        urlencode(entries[i].name, encoded_name, sizeof(encoded_name));

        // Build item_path
        if (strcmp(web_current_path, "/") == 0 || strcmp(web_current_path, "") == 0) {
            snprintf(item_path, sizeof(item_path), "/%s", encoded_name);
        } else {
            snprintf(item_path, sizeof(item_path), "%s/%s", web_current_path, encoded_name);
        }

        // Use item_path for links and display
        if (entries[i].is_directory) {
            offset += snprintf(body + offset, body_size - offset,
                               "<tr><td class=\"directory\"><a href=\"%s\">[ %s ]</a></td><td>-</td><td>%s</td></tr>",
                               item_path, entries[i].name, entries[i].time_str);
        } else {
            offset += snprintf(body + offset, body_size - offset,
                               "<tr><td><a href=\"%s\">%s</a></td><td>%s</td><td>%s</td></tr>",
                               item_path, entries[i].name, entries[i].size_str, entries[i].time_str);
        }
    }

    offset += snprintf(body + offset, body_size - offset, "</table>");

    // Footer and closing HTML
    offset += snprintf(body + offset, body_size - offset, "%s", HTML_BODY_END);

    return body;
}

/* Utility Functions */

void send_directory_listing(int client_socket, const char *request_path, const char *status_message) {
    char directory_path[512];
    char current_path[256];
    FileEntry entries[256];
    int num_entries;
    char *body;
    char cleaned_request_path[256];
    const char *req_path;
    char *p;

    // Clean up request_path by removing leading '.' and path separators
    req_path = request_path;
    while (*req_path == '.' || *req_path == '/' || *req_path == '\\') {
        req_path++;
    }
    strncpy(cleaned_request_path, req_path, sizeof(cleaned_request_path) - 1);
    cleaned_request_path[sizeof(cleaned_request_path) - 1] = '\0';

    // Build directory_path
    if (strlen(cleaned_request_path) == 0) {
        snprintf(directory_path, sizeof(directory_path), "%s", base_directory);
    } else {
        snprintf(directory_path, sizeof(directory_path), "%s%c%s", base_directory, PATH_SEPARATOR, cleaned_request_path);
    }

    // On Windows, replace forward slashes with backslashes in directory_path
#ifdef _WIN32
    p = directory_path;
    while (*p) {
        if (*p == '/') *p = '\\';
        p++;
    }
#endif

    // Set current_path to the cleaned request path, with leading '/' added
    if (strlen(cleaned_request_path) == 0) {
        strcpy(current_path, "/");
    } else {
        snprintf(current_path, sizeof(current_path), "/%s", cleaned_request_path);
    }

    // Ensure current_path uses forward slashes
    p = current_path;
    while (*p) {
        if (*p == '\\') *p = '/';
        p++;
    }

    num_entries = get_directory_entries(directory_path, entries, 256);
    if (num_entries < 0) {
        send_response(client_socket, "500 Internal Server Error", "text/plain",
                      "Failed to read directory");
        return;
    }

    body = generate_directory_listing_html(entries, num_entries, current_path, status_message, text_file_content);
    if (!body) {
        send_response(client_socket, "500 Internal Server Error", "text/plain",
                      "Failed to generate directory listing");
        return;
    }

    send_response(client_socket, "200 OK", "text/html", body);
    free(body);
}

void serve_file(int client_socket, const char *request_path) {
    char decoded_path[256];
    char full_path[512];
    struct stat file_stat;
    int file_fd;
    ssize_t bytes_read;
    char buffer[8192];
    char *p;
    char header[512];
    int header_length;

    url_decode(request_path, decoded_path);
    sanitize_path(decoded_path);

    /* Build full_path using join_paths */
    join_paths(base_directory, decoded_path, full_path, sizeof(full_path));

    /* On Windows, replace forward slashes with backslashes in full_path */
#ifdef _WIN32
    p = full_path;
    while (*p) {
        if (*p == '/') *p = '\\';
        p++;
    }
#endif

    /* Proceed to open and serve the file */
    if (stat(full_path, &file_stat) != 0 || S_ISDIR(file_stat.st_mode)) {
        send_response(client_socket, "404 Not Found", "text/plain", "File not found.");
        return;
    }

    file_fd = open(full_path, O_RDONLY | O_BINARY);
    if (file_fd < 0) {
        send_response(client_socket, "500 Internal Server Error", "text/plain", "Failed to open file.");
        return;
    }

    /* Send headers */
    header_length = snprintf(header, sizeof(header),
                             "HTTP/1.1 200 OK\r\n"
                             "Content-Type: application/octet-stream\r\n"
                             "Content-Length: %ld\r\n"
                             "Connection: close\r\n"
                             "\r\n",
                             (long)file_stat.st_size);
    send(client_socket, header, header_length, 0);

    /* Send file content */
    while ((bytes_read = read(file_fd, buffer, sizeof(buffer))) > 0) {
        send(client_socket, buffer, bytes_read, 0);
    }

    close(file_fd);
}

void handle_text_submission(int client_socket, const char *body, size_t body_length, const char *current_path) {
    char *user_text = strstr(body, "user_text=");
    char decoded_text[CHUNK_SIZE];
    char full_path[512];
    char dir_path[512];
    int file_fd;
    ssize_t bytes_written;

    if (!user_text) {
        send_response(client_socket, "400 Bad Request", "text/plain",
                      "No text found in the submission");
        return;
    }
    user_text += strlen("user_text=");
    url_decode(user_text, decoded_text);
    sanitize_path(decoded_text);

    snprintf(full_path, sizeof(full_path), "%s%s%csubmitted_text.txt", base_directory, current_path, PATH_SEPARATOR);
    snprintf(dir_path, sizeof(dir_path), "%s%s", base_directory, current_path);
    mkdir_recursive(dir_path);

    file_fd = open(full_path, O_WRONLY | O_CREAT | O_APPEND | O_BINARY, 0644);
    if (file_fd < 0) {
        send_response(client_socket, "500 Internal Server Error",
                      "text/plain", "Cannot save submitted text");
        return;
    }
    bytes_written = write(file_fd, "\r\n", 2);
    if (bytes_written != 2) {
        close(file_fd);
        send_response(client_socket, "500 Internal Server Error",
                      "text/plain", "Failed to write to file");
        return;
    }
    bytes_written = write(file_fd, decoded_text, strlen(decoded_text));
    if (bytes_written != (ssize_t)strlen(decoded_text)) {
        close(file_fd);
        send_response(client_socket, "500 Internal Server Error",
                      "text/plain", "Failed to write to file");
        return;
    }
    close(file_fd);

    // Redirect back to the directory listing with a success message
    send_redirect(client_socket, current_path);
}

void handle_file_upload(int client_socket, const char *initial_body,
                        size_t initial_body_length, const char *boundary,
                        int content_length, const char *current_path) {
    /* Variable declarations at the beginning */
    char buffer[CHUNK_SIZE];
    ssize_t bytes_received;
    int file_fd = -1;
    char filename[256] = "";
    char boundary_str[256];
    size_t boundary_len;
    int files_uploaded = 0; /* Track the number of files uploaded */
    size_t total_processed = 0;
    int in_file = 0;
    char *data_ptr = (char *)initial_body;
    size_t data_len = initial_body_length;

    /* Buffer to hold incomplete data from previous read */
    char *leftover_data = NULL;
    size_t leftover_size = 0;

    int upload_complete = 0; /* Flag to indicate upload completion */

    /* Variables for path manipulation */
    char fs_current_path[256];
    char *p;

    /* Variables for loops and blocks */
    size_t buffer_data_len;
    size_t buffer_pos;
    size_t to_copy;
    char *boundary_pos;
    char *headers_end;
    char headers[1024];
    size_t headers_len;
    char *content_disposition;
    size_t boundary_offset;
    size_t data_to_write;
    ssize_t bytes_written;

    /* Build the boundary string */
    snprintf(boundary_str, sizeof(boundary_str), "--%s", boundary);
    boundary_len = strlen(boundary_str);

    /* Copy current_path to fs_current_path */
    strncpy(fs_current_path, current_path, sizeof(fs_current_path) - 1);
    fs_current_path[sizeof(fs_current_path) - 1] = '\0';

    /* Remove leading '/' from fs_current_path if present */
    if (fs_current_path[0] == '/') {
        memmove(fs_current_path, fs_current_path + 1, strlen(fs_current_path));
    }

    /* Replace forward slashes with PATH_SEPARATOR */
    p = fs_current_path;
    while (*p) {
        if (*p == '/') *p = PATH_SEPARATOR;
        p++;
    }

    /* Read and process data */
    while (total_processed < (size_t)content_length && !upload_complete) {
        buffer_data_len = 0;
        buffer_pos = 0;
        to_copy = 0;

        /* If we have leftover data from previous read, prepend it to the buffer */
        if (leftover_size > 0) {
            memmove(buffer, leftover_data, leftover_size);
            buffer_data_len = leftover_size;
            free(leftover_data);
            leftover_data = NULL;
            leftover_size = 0;
        } else {
            buffer_data_len = 0;
        }

        /* Copy data from initial_body if there's any left */
        if (data_len > 0) {
            to_copy = data_len < CHUNK_SIZE - buffer_data_len ? data_len : CHUNK_SIZE - buffer_data_len;
            memcpy(buffer + buffer_data_len, data_ptr, to_copy);
            buffer_data_len += to_copy;
            data_ptr += to_copy;
            data_len -= to_copy;
            total_processed += to_copy;
        } else {
            /* Read more data from the socket */
            bytes_received = recv(client_socket, buffer + buffer_data_len, CHUNK_SIZE - buffer_data_len, 0);
            if (bytes_received <= 0) {
                /* Error or connection closed */
                if (file_fd != -1) close(file_fd);
                close_socket(client_socket);
                return;
            }
            buffer_data_len += bytes_received;
            total_processed += bytes_received;
        }

        buffer_pos = 0;
        while (buffer_pos < buffer_data_len) {
            if (!in_file) {
                /* Look for boundary */
                boundary_pos = memmem(buffer + buffer_pos, buffer_data_len - buffer_pos, boundary_str, boundary_len);
                if (boundary_pos) {
                    buffer_pos = (size_t)(boundary_pos - buffer) + boundary_len;

                    /* Check if this is the end boundary */
                    if (buffer_pos + 1 < buffer_data_len && buffer[buffer_pos] == '-' && buffer[buffer_pos + 1] == '-') {
                        /* End boundary found */
                        upload_complete = 1;
                        break;
                    }

                    /* Parse headers */
                    headers_end = memmem(buffer + buffer_pos, buffer_data_len - buffer_pos, "\r\n\r\n", 4);
                    if (!headers_end) {
                        /* Headers are incomplete, save leftover data */
                        leftover_size = buffer_data_len - buffer_pos;
                        leftover_data = malloc(leftover_size);
                        if (!leftover_data) {
                            /* Memory allocation failed */
                            send_response(client_socket, "500 Internal Server Error", "text/plain", "Memory allocation failed.");
                            if (file_fd != -1) close(file_fd);
                            close_socket(client_socket);
                            return;
                        }
                        memcpy(leftover_data, buffer + buffer_pos, leftover_size);
                        buffer_pos = buffer_data_len; /* Move to end of buffer */
                        break; /* Read more data */
                    }

                    headers_len = (size_t)(headers_end - (buffer + buffer_pos));

                    if (headers_len >= sizeof(headers)) {
                        /* Headers too large */
                        send_response(client_socket, "400 Bad Request", "text/plain", "Headers too large");
                        if (file_fd != -1) close(file_fd);
                        close_socket(client_socket);
                        return;
                    }
                    memcpy(headers, buffer + buffer_pos, headers_len);
                    headers[headers_len] = '\0';

                    /* Extract filename */
                    filename[0] = '\0';
                    content_disposition = strstr(headers, "Content-Disposition:");
                    if (content_disposition) {
                        extract_filename(content_disposition, filename);
                    }

                    buffer_pos = (size_t)(headers_end - buffer) + 4; /* Move past headers and CRLF */

                    /* Open file if filename is found */
                    if (filename[0] != '\0') {
                        char file_path[1024];
                        char dir_path[1024];

                        /* Build the full file path using join_paths */
                        join_paths(base_directory, fs_current_path, dir_path, sizeof(dir_path));
                        join_paths(dir_path, filename, file_path, sizeof(file_path));

                        /* Ensure the directory exists */
                        mkdir_recursive(dir_path);

                        /* Open the file for writing */
                        file_fd = open(file_path, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
                        if (file_fd < 0) {
                            send_response(client_socket, "500 Internal Server Error",
                                          "text/plain", "Cannot save uploaded file");
                            close_socket(client_socket);
                            return;
                        }
                        in_file = 1;
                    }
                } else {
                    /* Boundary not found, adjust buffer_pos */
                    if (buffer_data_len - buffer_pos > boundary_len) {
                        buffer_pos = buffer_data_len - boundary_len;
                    } else {
                        /* Need more data to find boundary */
                        break;
                    }
                }
            } else {
                /* Look for boundary */
                boundary_pos = memmem(buffer + buffer_pos, buffer_data_len - buffer_pos, boundary_str, boundary_len);
                if (boundary_pos) {
                    /* Compute the offset of boundary_pos from the start of the buffer */
                    boundary_offset = (size_t)(boundary_pos - buffer);
                    /* Compute how much data to write */
                    data_to_write = boundary_offset - buffer_pos;
                    /* Exclude preceding \r\n if present */
                    if (boundary_offset >= 2 && buffer[boundary_offset - 2] == '\r' && buffer[boundary_offset - 1] == '\n') {
                        data_to_write -= 2;
                    }
                    if (data_to_write > 0) {
                        bytes_written = write(file_fd, buffer + buffer_pos, data_to_write);
                        if (bytes_written != (ssize_t)data_to_write) {
                            /* Handle write error */
                            send_response(client_socket, "500 Internal Server Error",
                                          "text/plain", "Failed to write to file.");
                            close(file_fd);
                            close_socket(client_socket);
                            return;
                        }
                    }
                    close(file_fd);
                    file_fd = -1;
                    in_file = 0;
                    files_uploaded++;
                    buffer_pos = boundary_offset;

                    /* Check if this is the end boundary */
                    if (buffer_pos + boundary_len + 1 < buffer_data_len &&
                        strncmp(buffer + buffer_pos, boundary_str, boundary_len) == 0 &&
                        buffer[buffer_pos + boundary_len] == '-' && buffer[buffer_pos + boundary_len + 1] == '-') {
                        /* End boundary found */
                        upload_complete = 1;
                        break;
                    }
                } else {
                    /* Write all remaining data except the last boundary_len bytes */
                    if (buffer_data_len - buffer_pos > boundary_len) {
                        data_to_write = buffer_data_len - buffer_pos - boundary_len;
                        bytes_written = write(file_fd, buffer + buffer_pos, data_to_write);
                        if (bytes_written != (ssize_t)data_to_write) {
                            /* Handle write error */
                            send_response(client_socket, "500 Internal Server Error",
                                          "text/plain", "Failed to write to file.");
                            close(file_fd);
                            close_socket(client_socket);
                            return;
                        }
                        buffer_pos += data_to_write;
                    } else {
                        /* Not enough data, save leftover for next read */
                        leftover_size = buffer_data_len - buffer_pos;
                        leftover_data = malloc(leftover_size);
                        if (!leftover_data) {
                            /* Memory allocation failed */
                            send_response(client_socket, "500 Internal Server Error", "text/plain", "Memory allocation failed.");
                            if (file_fd != -1) close(file_fd);
                            close_socket(client_socket);
                            return;
                        }
                        memcpy(leftover_data, buffer + buffer_pos, leftover_size);
                        buffer_pos = buffer_data_len;
                        break;
                    }
                }
            }
        }
    }

    /* Clean up */
    if (file_fd != -1) {
        close(file_fd);
    }
    if (leftover_data) {
        free(leftover_data);
    }

    /* Send a response back to the client */
    if (files_uploaded > 0) {
        /* Redirect back to the directory listing */
        send_redirect(client_socket, current_path);
    } else {
        /* Send an error message indicating no files were selected */
        send_response(client_socket, "400 Bad Request", "text/plain",
                      "No files were selected for upload.");
    }
}


void handle_folder_creation(int client_socket, const char *body, size_t body_length, const char *current_path) {
    char *folder_name_param = strstr(body, "folder_name=");
    char folder_name[256];
    char new_folder_path[512];

    if (!folder_name_param) {
        send_response(client_socket, "400 Bad Request", "text/plain",
                      "No folder name provided.");
        return;
    }
    folder_name_param += strlen("folder_name=");
    url_decode(folder_name_param, folder_name);
    sanitize_path(folder_name);

    if (strlen(folder_name) == 0) {
        send_response(client_socket, "400 Bad Request", "text/plain",
                      "Invalid folder name.");
        return;
    }

    snprintf(new_folder_path, sizeof(new_folder_path), "%s%s%c%s", base_directory, current_path, PATH_SEPARATOR, folder_name);

    if (mkdir(new_folder_path, 0755) == 0) {
        // Folder created successfully, redirect back
        send_redirect(client_socket, current_path);
    } else {
        send_response(client_socket, "500 Internal Server Error", "text/plain",
                      "Failed to create folder.");
    }
}


void print_help() {
    printf("Usage: webbridge [folder_to_share] [port_number] [text_file_name]\n");
    printf("Options:\n");
    printf("  folder_to_share : The directory to share (default is current directory)\n");
    printf("  port_number     : The port number to listen on (default is 8080)\n");
    printf("  text_file_name  : Name of a text file whose content will be displayed on the page\n");
}

void handle_get_request(int client_socket, HttpRequest *request) {
    char decoded_path[256];
    char full_path[512];
    struct stat path_stat;

    url_decode(request->path, decoded_path);
    sanitize_path(decoded_path);

    // Build the full path
    if (decoded_path[0] == '\0') {
        // If decoded_path is empty, use base_directory directly
        snprintf(full_path, sizeof(full_path), "%s", base_directory);
    } else {
        snprintf(full_path, sizeof(full_path), "%s%s%s", base_directory, PATH_SEPARATOR_STR, decoded_path);
    }

    // Debugging output
    printf("base_directory: '%s'\n", base_directory);
    printf("PATH_SEPARATOR_STR: '%s'\n", PATH_SEPARATOR_STR);
    printf("decoded_path: '%s'\n", decoded_path);
    printf("Constructed full_path: '%s'\n", full_path);

    if (stat(full_path, &path_stat) == 0) {
        if (S_ISDIR(path_stat.st_mode)) {
//            send_directory_listing(client_socket, decoded_path, "");
            send_directory_listing(client_socket, full_path, "");
        } else {
            serve_file(client_socket, decoded_path);
        }
    } else {
        perror("stat");
        send_response(client_socket, "404 Not Found", "text/plain",
                      "File or directory not found");
    }
}

void handle_post_request(int client_socket, HttpRequest *request) {
    // Initialize current_path
    char current_path[256];
    // Variable declarations at the top
    char content_type[128];
    char *boundary_start;
    char boundary[256];

    if (strncmp(request->path, "/upload", strlen("/upload")) == 0) {
        // Handle file uploads
        // Extract the path after /upload
        const char *path_after_upload = request->path + strlen("/upload");

        // Skip any leading '/' in path_after_upload
        while (*path_after_upload == '/') {
            path_after_upload++;
        }

        // Prepend '/' to path_after_upload to form current_path
        if (*path_after_upload) {
            snprintf(current_path, sizeof(current_path), "/%s", path_after_upload);
        } else {
            strcpy(current_path, "/");
        }

        // Extract boundary from Content-Type header
        if (get_header_value(request->headers, "Content-Type", content_type, sizeof(content_type)) == -1) {
            send_response(client_socket, "400 Bad Request", "text/plain", "Content-Type header missing");
            return;
        }

        boundary_start = strstr(content_type, "boundary=");
        if (!boundary_start) {
            send_response(client_socket, "400 Bad Request", "text/plain", "Boundary not found");
            return;
        }

        snprintf(boundary, sizeof(boundary), "%s", boundary_start + 9); // Skip "boundary="

        // Call your existing handle_file_upload function
        handle_file_upload(client_socket, request->body, request->body_length, boundary, request->content_length, current_path);

    } else if (strncmp(request->path, "/create_folder", strlen("/create_folder")) == 0) {
        // Handle folder creation
        // Extract current path after "/create_folder"
        const char *path_after_create_folder = request->path + strlen("/create_folder");

        // Skip any leading '/' in path_after_create_folder
        while (*path_after_create_folder == '/') {
            path_after_create_folder++;
        }

        // Prepend '/' to path_after_create_folder to form current_path
        if (*path_after_create_folder) {
            snprintf(current_path, sizeof(current_path), "/%s", path_after_create_folder);
        } else {
            strcpy(current_path, "/");
        }

        // Call your existing handle_folder_creation function
        handle_folder_creation(client_socket, request->body, request->body_length, current_path);

    } else if (strncmp(request->path, "/submit_text", strlen("/submit_text")) == 0) {
        // Handle text submission
        // Extract current path after "/submit_text"
        const char *path_after_submit_text = request->path + strlen("/submit_text");

        // Skip any leading '/' in path_after_submit_text
        while (*path_after_submit_text == '/') {
            path_after_submit_text++;
        }

        // Prepend '/' to path_after_submit_text to form current_path
        if (*path_after_submit_text) {
            snprintf(current_path, sizeof(current_path), "/%s", path_after_submit_text);
        } else {
            strcpy(current_path, "/");
        }

        // Call your existing handle_text_submission function
        handle_text_submission(client_socket, request->body, request->body_length, current_path);

    } else {
        // Endpoint not recognized
        send_response(client_socket, "404 Not Found", "text/plain", "Endpoint not found.");
    }
}
/* HTTP Request Parsing */
int parse_http_request(int client_socket, HttpRequest *request) {
    char buffer[8192];
    int bytes_received, total_received = 0;
    char *header_end;
    int header_received = 0;
    int header_total_length;
    char *line_end;
    char *headers_start;
    size_t headers_length;
    char content_length_str[16];
    int content_length = 0;
    size_t body_length;
    int total_body_received = 0;
    char *body = NULL;

    memset(buffer, 0, sizeof(buffer));

    // Read until we have the full headers
    while ((bytes_received = recv(client_socket, buffer + total_received,
                                  (int)(sizeof(buffer) - total_received - 1), 0)) > 0) {
        total_received += bytes_received;
        buffer[total_received] = '\0';

        // Log the received data
        printf("Received data (%d bytes):\n%s\n", bytes_received, buffer + total_received - bytes_received);

        header_end = strstr(buffer, "\r\n\r\n");
        if (header_end) {
            header_received = 1;
            break;
        }
        if (total_received >= (int)(sizeof(buffer) - 1)) {
            // Header too large
            return -1;
        }
    }

    if (bytes_received <= 0 || !header_received) {
        // Error or connection closed, or headers not fully received
        return -1;
    }

    // Parse request line
    line_end = strstr(buffer, "\r\n");
    if (!line_end) {
        // Invalid request
        return -1;
    }
    *line_end = '\0'; // Null-terminate the request line
    sscanf(buffer, "%s %s %s", request->method, request->path, request->protocol);

    // Separate path and query string
    {
        char *question_mark = strchr(request->path, '?');
        if (question_mark) {
            *question_mark = '\0';
            // Optionally store the query string if needed
            // request->query_string = question_mark + 1;
        }
    }

    // Move past the request line
    headers_start = line_end + 2; // Skip "\r\n"

    // Calculate headers length
    headers_length = (size_t)(header_end - headers_start);
    if (headers_length >= sizeof(request->headers)) {
        // Headers too large
        return -1;
    }

    // Copy headers
    memcpy(request->headers, headers_start, headers_length);
    request->headers[headers_length] = '\0';

    // Extract Content-Length
    if (get_header_value(request->headers, "Content-Length", content_length_str, sizeof(content_length_str)) == 0) {
        content_length = atoi(content_length_str);
    }

    // Read the body
    header_total_length = (int)((header_end - buffer) + 4); // Include "\r\n\r\n"
    body_length = (size_t)(total_received - header_total_length);
    total_body_received = (int)body_length;

    if (content_length > 0) {
        body = (char *)malloc(content_length + 1); // +1 for null-terminator if needed
        if (!body) {
            // Memory allocation failed
            return -1;
        }

        if (body_length > 0) {
            memcpy(body, buffer + header_total_length, body_length);
        }

        while (total_body_received < content_length) {
            bytes_received = recv(client_socket, body + total_body_received, content_length - total_body_received, 0);
            if (bytes_received <= 0) {
                // Error or connection closed
                free(body);
                return -1;
            }
            total_body_received += bytes_received;
        }

        body[content_length] = '\0'; // Null-terminate if treating as a string
    } else {
        // No body to read
        body = NULL;
    }

    request->body = body;
    request->body_length = (size_t)content_length;
    request->content_length = content_length;

    return 0;
}

void handle_request(int client_socket) {
    HttpRequest request;
    memset(&request, 0, sizeof(request));

    if (parse_http_request(client_socket, &request) == -1) {
        // Handle parsing error
        send_response(client_socket, "400 Bad Request", "text/plain", "Failed to parse HTTP request.");
        close_socket(client_socket);
        return;
    }

    // Process request...
    if (strcmp(request.method, "POST") == 0) {
        handle_post_request(client_socket, &request);
    } else if (strcmp(request.method, "GET") == 0) {
        handle_get_request(client_socket, &request);
    } else {
        send_response(client_socket, "501 Not Implemented", "text/plain", "Method not implemented.");
    }

    // Clean up
    if (request.body) {
        free(request.body);
    }

    close_socket(client_socket);
}
#ifdef _WIN32
int start_server(int port) {
    WSADATA wsaData;
    int wsaInitResult;
    int server_socket;
    struct sockaddr_in server_addr;
    int opt = 1;

    wsaInitResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (wsaInitResult != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", wsaInitResult);
        return -1;
    }

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == INVALID_SOCKET) {
        fprintf(stderr, "Socket creation failed: %ld\n", WSAGetLastError());
        WSACleanup();
        return -1;
    }

    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt)) == SOCKET_ERROR) {
        fprintf(stderr, "setsockopt failed: %d\n", WSAGetLastError());
        closesocket(server_socket);
        WSACleanup();
        return -1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        fprintf(stderr, "Bind failed: %d\n", WSAGetLastError());
        closesocket(server_socket);
        WSACleanup();
        return -1;
    }

    if (listen(server_socket, 10) == SOCKET_ERROR) {
        fprintf(stderr, "Listen failed: %d\n", WSAGetLastError());
        closesocket(server_socket);
        WSACleanup();
        return -1;
    }

    return server_socket;
}
#else
int start_server(int port) {
    int server_socket;
    struct sockaddr_in server_addr;
    int opt = 1;

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Socket creation failed");
        return -1;
    }

    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        perror("setsockopt failed");
        close(server_socket);
        return -1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_socket);
        return -1;
    }

    if (listen(server_socket, 10) < 0) {
        perror("Listen failed");
        close(server_socket);
        return -1;
    }

    return server_socket;
}
#endif

int main(int argc, char *argv[]) {
    char cwd[512];
    int server_socket;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    setlocale(LC_NUMERIC, "");

    if (argc > 1) {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            print_help();
            return 0;
        }
        strncpy(base_directory, argv[1], sizeof(base_directory) - 1);
        base_directory[sizeof(base_directory) - 1] = '\0';
    }

    if (argc > 2) {
        server_port = atoi(argv[2]);
        if (server_port <= 0 || server_port > 65535) {
            fprintf(stderr, "Invalid port number.\n");
            return 1;
        }
    }

    if (argc > 3) {
        char full_text_path[512];
        FILE *text_file;
        long file_size;

        snprintf(full_text_path, sizeof(full_text_path), "%s/%s", base_directory, argv[3]);
        text_file = fopen(full_text_path, "r");
        if (text_file) {
            fseek(text_file, 0, SEEK_END);
            file_size = ftell(text_file);
            fseek(text_file, 0, SEEK_SET);
            if (file_size > 102400) {
                file_size = 102400;
            }
            text_file_content = malloc(file_size + 1);
            if (text_file_content == NULL) {
                fprintf(stderr, "Memory allocation failed for text file content.\n");
                fclose(text_file);
                exit(EXIT_FAILURE);
            }
            if (fread(text_file_content, 1, file_size, text_file) != (size_t)file_size) {
                fprintf(stderr, "Failed to read text file content.\n");
            }
            text_file_content[file_size] = '\0'; // Ensure null termination
            fclose(text_file);
        } else {
            fprintf(stderr, "Failed to open text file: %s\n", full_text_path);
            text_file_content = malloc(1);
            if (text_file_content == NULL) {
                fprintf(stderr, "Memory allocation failed.\n");
                exit(EXIT_FAILURE);
            }
            text_file_content[0] = '\0';
        }
    }

#ifndef _WIN32
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        printf("Current working directory: %s\n", cwd);
    } else {
        perror("getcwd() error");
    }
#else
    if (_getcwd(cwd, sizeof(cwd)) != NULL) {
        printf("Current working directory: %s\n", cwd);
    } else {
        perror("getcwd() error");
    }
#endif

    server_socket = start_server(server_port);
    if (server_socket < 0) {
        fprintf(stderr, "Failed to start server on port %d.\n", server_port);
        return 1;
    }

    printf("HTTP server running on port %d, serving directory '%s'\n", server_port, base_directory);

    while (1) {
        int client_socket =
#ifdef _WIN32
            accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket == INVALID_SOCKET) {
            fprintf(stderr, "Accept failed: %d\n", WSAGetLastError());
#else
            accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket < 0) {
            perror("Accept failed");
#endif
            continue;
        }

        printf("Accepted connection from %s\n", inet_ntoa(client_addr.sin_addr));
        handle_request(client_socket);
    }

#ifdef _WIN32
    closesocket(server_socket);
    WSACleanup();
#else
    close(server_socket);
#endif

    if (text_file_content) free(text_file_content);
    return 0;
}
