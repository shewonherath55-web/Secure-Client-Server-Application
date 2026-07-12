#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
#include <sys/stat.h>
#include <ctype.h>

#define PORT 50409
#define SID "1024"
#define MAX_PAYLOAD 4096
#define BUFFER_SIZE 8192

// structure to hold partial data for protocol parsing
typedef struct {
    char buffer[BUFFER_SIZE];
    int buffer_len;
} ProtocolState;

// user and session limits
#define MAX_USERS 100
#define MAX_SESSIONS 100
#define TOKEN_EXPIRY 300
#define USER_FILE "users.dat"
#define SESSION_FILE "sessions.dat"

// user structure for registration
struct User {
    char username[32];
    char salt[32];
    char hash[65];
};

// session structure for logged in users
struct Session {
    char token[65];
    char username[32];
    time_t last_activity;
    int active;
};

// global arrays
struct User users[MAX_USERS];
int user_count = 0;
struct Session sessions[MAX_SESSIONS];
int session_count = 0;

// rate limiting structures
#define MAX_REQUESTS_PER_MINUTE 10
#define RATE_WINDOW 60

struct RateLimit {
    char ip[16];
    int count;
    time_t window_start;
    struct RateLimit *next;
};

struct RateLimit *rate_limits = NULL;

// brute force lockout structures
#define MAX_FAILED_ATTEMPTS 5
#define LOCKOUT_DURATION 300

struct FailedAttempt {
    char username[32];
    int failed_count;
    time_t lockout_until;
    struct FailedAttempt *next;
};

struct FailedAttempt *failed_attempts = NULL;

// log file
#define LOG_FILE "server_IT24102409.log"
FILE *log_file = NULL;

// write to log file
void write_log(const char *event_type, const char *username, 
               const char *command, const char *result, 
               struct sockaddr_in client_addr, int pid) {
    if (!log_file) return;
    
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[64];
    char client_ip[INET_ADDRSTRLEN];
    
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
    int client_port = ntohs(client_addr.sin_port);
    
    fprintf(log_file, "[%s] %s:%d | PID:%d | User:%s | Cmd:%s | Result:%s | %s\n",
            timestamp, client_ip, client_port, pid, username, command, result, event_type);
    fflush(log_file);
}

// load users from file
void load_users() {
    FILE *fp = fopen(USER_FILE, "rb");
    if (fp) {
        fread(&user_count, sizeof(int), 1, fp);
        fread(users, sizeof(struct User), user_count, fp);
        fclose(fp);
    }
}

// save users to file
void save_users() {
    FILE *fp = fopen(USER_FILE, "wb");
    if (fp) {
        fwrite(&user_count, sizeof(int), 1, fp);
        fwrite(users, sizeof(struct User), user_count, fp);
        fclose(fp);
    }
}

// load sessions from file
void load_sessions() {
    FILE *fp = fopen(SESSION_FILE, "rb");
    if (fp) {
        fread(&session_count, sizeof(int), 1, fp);
        fread(sessions, sizeof(struct Session), session_count, fp);
        fclose(fp);
    }
}

// save sessions to file
void save_sessions() {
    FILE *fp = fopen(SESSION_FILE, "wb");
    if (fp) {
        fwrite(&session_count, sizeof(int), 1, fp);
        fwrite(sessions, sizeof(struct Session), session_count, fp);
        fclose(fp);
    }
}

// load failed attempts from file
void load_failed_attempts() {
    FILE *fp = fopen("failed.dat", "rb");
    if (fp) {
        int count;
        fread(&count, sizeof(int), 1, fp);
        for (int i = 0; i < count; i++) {
            struct FailedAttempt *new_fa = malloc(sizeof(struct FailedAttempt));
            fread(new_fa, sizeof(struct FailedAttempt), 1, fp);
            new_fa->next = failed_attempts;
            failed_attempts = new_fa;
        }
        fclose(fp);
    }
}

// save failed attempts to file
void save_failed_attempts() {
    FILE *fp = fopen("failed.dat", "wb");
    if (fp) {
        int count = 0;
        struct FailedAttempt *fa = failed_attempts;
        while (fa) {
            count++;
            fa = fa->next;
        }
        fwrite(&count, sizeof(int), 1, fp);
        fa = failed_attempts;
        while (fa) {
            fwrite(fa, sizeof(struct FailedAttempt), 1, fp);
            fa = fa->next;
        }
        fclose(fp);
    }
}

// create sha256 hash of input string
void sha256_hash(const char *input, char *output) {
    char cmd[1024];
    char escaped_input[900];
    strncpy(escaped_input, input, sizeof(escaped_input) - 1);
    escaped_input[sizeof(escaped_input) - 1] = '\0';
    
    int needed = snprintf(cmd, sizeof(cmd), "echo -n '%s' | sha256sum", escaped_input);
    if (needed >= (int)sizeof(cmd)) {
        strcpy(output, "0000000000000000000000000000000000000000000000000000000000000000");
        return;
    }
    
    FILE *fp = popen(cmd, "r");
    if (fp) {
        fgets(output, 65, fp);
        char *space = strchr(output, ' ');
        if (space) *space = '\0';
        pclose(fp);
    } else {
        strcpy(output, "0000000000000000000000000000000000000000000000000000000000000000");
    }
}

// generate random salt for password hashing
void generate_salt(char *salt, int len) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    srand(time(NULL) ^ getpid());
    for (int i = 0; i < len - 1; i++) {
        salt[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    salt[len - 1] = '\0';
}

// generate session token for logged in user
void generate_token(char *token, const char *username) {
    char input[256];
    snprintf(input, sizeof(input), "%s%ld%d", username, (long)time(NULL), rand());
    sha256_hash(input, token);
}

// find user by username
struct User* find_user(const char *username) {
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].username, username) == 0) {
            return &users[i];
        }
    }
    return NULL;
}

// find session by token
struct Session* find_session(const char *token) {
    time_t now = time(NULL);
    for (int i = 0; i < session_count; i++) {
        if (sessions[i].active && strcmp(sessions[i].token, token) == 0) {
            if (now - sessions[i].last_activity <= TOKEN_EXPIRY) {
                sessions[i].last_activity = now;
                return &sessions[i];
            } else {
                sessions[i].active = 0;
            }
        }
    }
    return NULL;
}

// create new session for user
char* create_session(const char *username) {
    char token[65];
    generate_token(token, username);
    
    for (int i = 0; i < session_count; i++) {
        if (!sessions[i].active) {
            strcpy(sessions[i].token, token);
            strcpy(sessions[i].username, username);
            sessions[i].last_activity = time(NULL);
            sessions[i].active = 1;
            save_sessions();
            return sessions[i].token;
        }
    }
    
    if (session_count < MAX_SESSIONS) {
        strcpy(sessions[session_count].token, token);
        strcpy(sessions[session_count].username, username);
        sessions[session_count].last_activity = time(NULL);
        sessions[session_count].active = 1;
        session_count++;
        save_sessions();
        return sessions[session_count - 1].token;
    }
    return NULL;
}

// check rate limit for client ip
int check_rate_limit(const char *client_ip, struct sockaddr_in client_addr, int pid) {
    time_t now = time(NULL);
    struct RateLimit *rl = rate_limits;
    struct RateLimit *prev = NULL;
    
    while (rl) {
        if (strcmp(rl->ip, client_ip) == 0) {
            if (now - rl->window_start >= RATE_WINDOW) {
                rl->count = 1;
                rl->window_start = now;
                return 1;
            }
            
            if (rl->count < MAX_REQUESTS_PER_MINUTE) {
                rl->count++;
                return 1;
            } else {
                write_log("RATE_LIMIT", "anonymous", "request", "exceeded", client_addr, pid);
                return 0;
            }
        }
        prev = rl;
        rl = rl->next;
    }
    
    struct RateLimit *new_rl = malloc(sizeof(struct RateLimit));
    strcpy(new_rl->ip, client_ip);
    new_rl->count = 1;
    new_rl->window_start = now;
    new_rl->next = NULL;
    
    if (prev) {
        prev->next = new_rl;
    } else {
        rate_limits = new_rl;
    }
    
    return 1;
}

// check if account is locked
int is_account_locked(const char *username, struct sockaddr_in client_addr, int pid) {
    time_t now = time(NULL);
    struct FailedAttempt *fa = failed_attempts;
    
    while (fa) {
        if (strcmp(fa->username, username) == 0) {
            if (now < fa->lockout_until) {
                int remaining = (int)(fa->lockout_until - now);
                printf("[LOCKOUT] Account %s is LOCKED for %d more seconds\n", username, remaining);
                write_log("LOCKED_ACCESS", username, "LOGIN", "account locked", client_addr, pid);
                return 1;
            }
        }
        fa = fa->next;
    }
    return 0;
}

// record failed login attempt
void record_failed_attempt(const char *username, struct sockaddr_in client_addr, int pid) {
    time_t now = time(NULL);
    struct FailedAttempt *fa = failed_attempts;
    
    while (fa) {
        if (strcmp(fa->username, username) == 0) {
            fa->failed_count++;
            printf("[LOCKOUT] User %s failed attempt %d/%d\n", username, fa->failed_count, MAX_FAILED_ATTEMPTS);
            
            if (fa->failed_count >= MAX_FAILED_ATTEMPTS) {
                fa->lockout_until = now + LOCKOUT_DURATION;
                printf("[LOCKOUT] User %s is NOW LOCKED for %d seconds\n", username, LOCKOUT_DURATION);
                write_log("LOCKOUT_TRIGGER", username, "LOGIN", "too many failed attempts", client_addr, pid);
            }
            save_failed_attempts();
            return;
        }
        fa = fa->next;
    }
    
    // new failed attempt record
    struct FailedAttempt *new_fa = malloc(sizeof(struct FailedAttempt));
    strcpy(new_fa->username, username);
    new_fa->failed_count = 1;
    new_fa->lockout_until = 0;
    new_fa->next = failed_attempts;
    failed_attempts = new_fa;
    printf("[LOCKOUT] User %s first failed attempt\n", username);
    save_failed_attempts();
}

// reset failed attempts after successful login
void reset_failed_attempts(const char *username) {
    struct FailedAttempt *fa = failed_attempts;
    
    while (fa) {
        if (strcmp(fa->username, username) == 0) {
            fa->failed_count = 0;
            fa->lockout_until = 0;
            printf("[LOCKOUT] User %s failed attempts reset\n", username);
            save_failed_attempts();
            return;
        }
        fa = fa->next;
    }
}

// validate username format
int validate_username(const char *username) {
    int len = strlen(username);
    if (len < 3 || len > 20) return 0;
    for (int i = 0; i < len; i++) {
        if (!isalnum(username[i])) return 0;
    }
    if (strcmp(username, "admin") == 0 || 
        strcmp(username, "root") == 0 ||
        strcmp(username, "system") == 0) {
        return 0;
    }
    return 1;
}

// register new user
int register_user(const char *username, const char *password, struct sockaddr_in client_addr, int pid) {
    if (!validate_username(username)) {
        write_log("REGISTER_FAIL", username, "REGISTER", "invalid username", client_addr, pid);
        return -3;
    }
    
    if (find_user(username) != NULL) {
        write_log("REGISTER_FAIL", username, "REGISTER", "user already exists", client_addr, pid);
        return -1;
    }
    
    if (user_count >= MAX_USERS) {
        write_log("REGISTER_FAIL", username, "REGISTER", "max users reached", client_addr, pid);
        return -2;
    }
    
    struct User new_user;
    strcpy(new_user.username, username);
    generate_salt(new_user.salt, 32);
    
    char salted_password[256];
    snprintf(salted_password, sizeof(salted_password), "%s%s", new_user.salt, password);
    sha256_hash(salted_password, new_user.hash);
    
    users[user_count] = new_user;
    user_count++;
    save_users();
    
    char dir_path[256];
    snprintf(dir_path, sizeof(dir_path), "/srv/ie2102/IT24102409/%s", username);
    mkdir(dir_path, 0755);
    
    printf("[REGISTER] New user: %s\n", username);
    write_log("REGISTER_SUCCESS", username, "REGISTER", "success", client_addr, pid);
    return 0;
}

// login user
char* login_user(const char *username, const char *password, struct sockaddr_in client_addr, int pid) {
    // FIRST: Check if account is locked
    if (is_account_locked(username, client_addr, pid)) {
        write_log("LOGIN_FAIL", username, "LOGIN", "account locked", client_addr, pid);
        return NULL;
    }
    
    struct User *user = find_user(username);
    if (user == NULL) {
        record_failed_attempt(username, client_addr, pid);
        write_log("LOGIN_FAIL", username, "LOGIN", "user not found", client_addr, pid);
        return NULL;
    }
    
    char salted_password[256];
    snprintf(salted_password, sizeof(salted_password), "%s%s", user->salt, password);
    char hash[65];
    sha256_hash(salted_password, hash);
    
    if (strcmp(hash, user->hash) != 0) {
        record_failed_attempt(username, client_addr, pid);
        write_log("LOGIN_FAIL", username, "LOGIN", "wrong password", client_addr, pid);
        return NULL;
    }
    
    // Successful login - reset failed attempts
    reset_failed_attempts(username);
    write_log("LOGIN_SUCCESS", username, "LOGIN", "success", client_addr, pid);
    printf("[LOGIN] User %s logged in successfully\n", username);
    return create_session(username);
}

// logout user
int logout_user(const char *token, struct sockaddr_in client_addr, int pid) {
    struct Session *session = find_session(token);
    if (session == NULL) return -1;
    write_log("LOGOUT", session->username, "LOGOUT", "success", client_addr, pid);
    printf("[LOGOUT] User %s logged out\n", session->username);
    session->active = 0;
    save_sessions();
    return 0;
}

// signal handler to prevent zombie processes
void sigchld_handler(int sig) {
    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

// parse LEN:<n> protocol format
int parse_message(char *buffer, int *offset, int buffer_len, char **payload, int *payload_len) {
    char *newline = strstr(buffer + *offset, "\n");
    if (!newline) return 1;
    
    *newline = '\0';
    if (strncmp(buffer + *offset, "LEN:", 4) != 0) return -1;
    
    int len = atoi(buffer + *offset + 4);
    if (len <= 0) return -1;
    if (len > MAX_PAYLOAD) return -2;
    
    int header_len = (newline - (buffer + *offset)) + 1;
    int payload_start = *offset + header_len;
    if (payload_start + len > buffer_len) return 1;
    
    *payload = buffer + payload_start;
    *payload_len = len;
    *offset = payload_start + len;
    
    *newline = '\n';
    return 0;
}

// send response to client
void send_response(int client_fd, int is_ok, int code, char *message) {
    char response[BUFFER_SIZE];
    if (is_ok) {
        snprintf(response, sizeof(response), "OK %d SID:%s %s\n", code, SID, message);
    } else {
        snprintf(response, sizeof(response), "ERR %d SID:%s %s\n", code, SID, message);
    }
    send(client_fd, response, strlen(response), 0);
}

// send response with token
void send_response_with_token(int client_fd, int is_ok, int code, char *message, char *token) {
    char response[BUFFER_SIZE];
    if (is_ok) {
        snprintf(response, sizeof(response), "OK %d SID:%s %s TOKEN:%s\n", code, SID, message, token);
    } else {
        snprintf(response, sizeof(response), "ERR %d SID:%s %s\n", code, SID, message);
    }
    send(client_fd, response, strlen(response), 0);
}

// handle each client connection
void handle_client(int client_fd, struct sockaddr_in client_addr) {
    ProtocolState state;
    state.buffer_len = 0;
    int offset = 0;
    
    int pid = getpid();
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
    
    char current_token[65] = "";
    char current_user[32] = "anonymous";
    
    load_users();
    load_sessions();
    load_failed_attempts();
    
    printf("[PID %d] Client connected from %s\n", pid, client_ip);
    write_log("CONNECTION", "anonymous", "connect", "success", client_addr, pid);
    
    while (1) {
        if (!check_rate_limit(client_ip, client_addr, pid)) {
            send_response(client_fd, 0, 429, "Rate limit exceeded. Try again later.");
            break;
        }
        
        int bytes = recv(client_fd, state.buffer + state.buffer_len, 
                        BUFFER_SIZE - state.buffer_len - 1, 0);
        if (bytes <= 0) break;
        
        state.buffer_len += bytes;
        state.buffer[state.buffer_len] = '\0';
        
        while (offset < state.buffer_len) {
            char *payload;
            int payload_len;
            int result = parse_message(state.buffer, &offset, state.buffer_len, 
                                      &payload, &payload_len);
            
            if (result == 0) {
                char command[payload_len + 1];
                memcpy(command, payload, payload_len);
                command[payload_len] = '\0';
                
                printf("[PID %d] Command: %s\n", pid, command);
                write_log("COMMAND", current_user, command, "received", client_addr, pid);
                
                char cmd[32], arg1[64], arg2[64];
                int parsed = sscanf(command, "%s %s %s", cmd, arg1, arg2);
                
                char *token_ptr = strstr(command, "TOKEN:");
                char extracted_token[65] = "";
                if (token_ptr) {
                    sscanf(token_ptr, "TOKEN:%s", extracted_token);
                    char *nl = strchr(extracted_token, '\n');
                    if (nl) *nl = '\0';
                }
                
                if (strcmp(cmd, "REGISTER") == 0 && parsed >= 3) {
                    int r = register_user(arg1, arg2, client_addr, pid);
                    if (r == 0) {
                        send_response(client_fd, 1, 200, "Registration successful");
                    } else if (r == -1) {
                        send_response(client_fd, 0, 400, "User already exists");
                    } else if (r == -3) {
                        send_response(client_fd, 0, 400, "Invalid username. Use 3-20 alphanumeric characters.");
                    } else {
                        send_response(client_fd, 0, 400, "Registration failed");
                    }
                }
                else if (strcmp(cmd, "LOGIN") == 0 && parsed >= 3) {
                    char *token = login_user(arg1, arg2, client_addr, pid);
                    if (token != NULL) {
                        strcpy(current_token, token);
                        strcpy(current_user, arg1);
                        send_response_with_token(client_fd, 1, 200, "Login successful", token);
                    } else {
                        if (is_account_locked(arg1, client_addr, pid)) {
                            send_response(client_fd, 0, 403, "Account locked. Too many failed attempts. Try again later.");
                        } else {
                            send_response(client_fd, 0, 401, "Login failed - invalid username or password");
                        }
                    }
                }
                else if (strcmp(cmd, "LOGOUT") == 0) {
                    if (strlen(extracted_token) > 0) {
                        logout_user(extracted_token, client_addr, pid);
                        send_response(client_fd, 1, 200, "Logout successful");
                        if (strcmp(current_token, extracted_token) == 0) {
                            current_token[0] = '\0';
                            strcpy(current_user, "anonymous");
                        }
                    } else if (strlen(current_token) > 0) {
                        logout_user(current_token, client_addr, pid);
                        current_token[0] = '\0';
                        strcpy(current_user, "anonymous");
                        send_response(client_fd, 1, 200, "Logout successful");
                    } else {
                        send_response(client_fd, 0, 400, "Not logged in");
                    }
                }
                else {
                    char *use_token = NULL;
                    if (strlen(extracted_token) > 0) {
                        use_token = extracted_token;
                    } else if (strlen(current_token) > 0) {
                        use_token = current_token;
                    }
                    
                    if (use_token == NULL) {
                        send_response(client_fd, 0, 401, "Authentication required. Please login first.");
                    } else {
                        struct Session *session = find_session(use_token);
                        if (session == NULL) {
                            send_response(client_fd, 0, 401, "Session expired. Please login again.");
                            if (strlen(current_token) > 0) {
                                current_token[0] = '\0';
                                strcpy(current_user, "anonymous");
                            }
                        } else {
                            strcpy(current_user, session->username);
                            strcpy(current_token, use_token);
                            send_response(client_fd, 1, 200, "Command received");
                            write_log("COMMAND_SUCCESS", current_user, command, "success", client_addr, pid);
                        }
                    }
                }
            } else if (result == -1) {
                send_response(client_fd, 0, 400, "Invalid protocol format");
                write_log("PROTOCOL_ERROR", "anonymous", "parse", "invalid format", client_addr, pid);
                offset = state.buffer_len;
                break;
            } else if (result == -2) {
                send_response(client_fd, 0, 400, "Payload too large (max 4096 bytes)");
                write_log("PAYLOAD_ERROR", "anonymous", "recv", "payload overflow", client_addr, pid);
                offset = state.buffer_len;
                break;
            } else if (result == 1) {
                break;
            }
        }
        
        if (offset == state.buffer_len) {
            state.buffer_len = 0;
            offset = 0;
        } else if (offset > 0) {
            memmove(state.buffer, state.buffer + offset, state.buffer_len - offset);
            state.buffer_len -= offset;
            offset = 0;
        }
    }
    
    printf("[PID %d] Client disconnected\n", pid);
    write_log("DISCONNECT", current_user, "disconnect", "success", client_addr, pid);
    close(client_fd);
}

int main() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    srand(time(NULL));
    
    load_users();
    load_sessions();
    load_failed_attempts();
    
    log_file = fopen(LOG_FILE, "a");
    if (!log_file) {
        perror("Failed to open log file");
        return 1;
    }
    
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    fprintf(log_file, "[%s] SERVER STARTUP | PID:%d | Users:%d | Sessions:%d\n", 
            timestamp, getpid(), user_count, session_count);
    fflush(log_file);
    
    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGCHLD, &sa, NULL);
    
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) return 1;
    
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) return 1;
    if (listen(server_fd, 10) < 0) return 1;
    
    printf("========================================\n");
    printf("Server running on port %d, SID:%s\n", PORT, SID);
    printf("Log file: %s\n", LOG_FILE);
    printf("Loaded %d users, %d sessions\n", user_count, session_count);
    printf("Lockout: %d failed attempts = %d second lockout\n", MAX_FAILED_ATTEMPTS, LOCKOUT_DURATION);
    printf("========================================\n");
    
    while (1) {
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) continue;
        
        pid_t pid = fork();
        if (pid < 0) {
            close(client_fd);
        } else if (pid == 0) {
            close(server_fd);
            handle_client(client_fd, client_addr);
            close(client_fd);
            exit(0);
        } else {
            close(client_fd);
        }
    }
    
    close(server_fd);
    fclose(log_file);
    return 0;
}
