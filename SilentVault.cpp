#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <stdexcept>
#include <termios.h>
#include <unistd.h>
#include <cstdlib>
#include <sys/stat.h>
#include <sys/types.h>
#include <cerrno>
#include <sodium.h>
#include <argon2.h>
#include <limits>

using namespace std;

#define RED "\e[0;31m"
#define GREEN "\e[0;32m"
#define YELLOW "\e[0;33m"
#define CYAN "\e[0;36m"
#define RESET "\e[0m"

const string D_TAG = "VERIFY-ME";
const string FILENAME = "system.enc";
const string DIRNAME = ".silentVault";

struct PasswordEntry {
    string service;
    string username;
    string password;
    bool corrupted = false;
    string entry_salt_hex;
    string nonce_hex;
    string ciphertext_hex;
};

// ----------------------------- Hex helpers -----------------------------
static string to_hex(const unsigned char* data, size_t len) {
    static const char hex_chars[] = "0123456789abcdef";
    string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        unsigned char b = data[i];
        out.push_back(hex_chars[(b >> 4) & 0x0F]);
        out.push_back(hex_chars[b & 0x0F]);
    }
    return out;
}

static vector<unsigned char> from_hex(const string& hex) {
    if (hex.size() % 2 != 0) throw runtime_error("Invalid hex string length");
    vector<unsigned char> out(hex.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        string byte_str = hex.substr(i * 2, 2);
        unsigned int v = 0;
        std::stringstream ss;
        ss << std::hex << byte_str;
        ss >> v;
        out[i] = static_cast<unsigned char>(v & 0xFF);
    }
    return out;
}

// ------------------------- Salt generation -----------------------------
string generate_salt_hex(size_t salt_len = 32) {
    vector<unsigned char> salt(salt_len);
    randombytes_buf(salt.data(), salt.size());
    return to_hex(salt.data(), salt.size());
}

// ----------------------------- Argon2id KDF ----------------------------
string derive_key_hex_from_password(const string& password, const string& salt_hex) {
    const uint32_t t_cost = 4;
    const uint32_t m_cost = 1 << 16; 
    const uint32_t parallelism = 4;
    const uint32_t key_len = 32;

    vector<unsigned char> salt = from_hex(salt_hex);
    vector<unsigned char> key(key_len);

    int result = argon2id_hash_raw(
        t_cost, m_cost, parallelism,
        password.data(), password.size(),
        salt.data(), salt.size(),
        key.data(), key.size()
    );

    if (result != ARGON2_OK) {
        throw runtime_error(string("Argon2 error: ") + argon2_error_message(result));
    }

    string key_hex = to_hex(key.data(), key.size());
    sodium_memzero(key.data(), key.size());

    return key_hex;
}

// ------------------------- XChaCha20-Poly1305 -------------------------
string encrypt_xchacha_hex_with_key(const string& plaintext, const string& key_hex, const string& aad_hex, string& nonce_hex_out) {
    vector<unsigned char> key = from_hex(key_hex);
    if (key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) throw runtime_error("Invalid key length");

    vector<unsigned char> aad = from_hex(aad_hex);
    vector<unsigned char> nonce(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    randombytes_buf(nonce.data(), nonce.size());

    size_t clen = plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    vector<unsigned char> ciphertext(clen);
    unsigned long long outlen = 0;

    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
        ciphertext.data(), &outlen,
        reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size(),
        aad.data(), aad.size(),
        NULL, nonce.data(), key.data()) != 0) {
        sodium_memzero(key.data(), key.size());
        throw runtime_error("Encryption failed");
    }

    nonce_hex_out = to_hex(nonce.data(), nonce.size());
    string ciphertext_hex = to_hex(ciphertext.data(), outlen);

    sodium_memzero(key.data(), key.size());
    sodium_memzero(ciphertext.data(), ciphertext.size());

    return ciphertext_hex;
}

string decrypt_xchacha_hex_with_key(const string& nonce_hex, const string& ciphertext_hex, const string& key_hex, const string& aad_hex) {
    vector<unsigned char> key = from_hex(key_hex);
    if (key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) throw runtime_error("Invalid key length");

    vector<unsigned char> nonce = from_hex(nonce_hex);
    if (nonce.size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) throw runtime_error("Invalid nonce length");

    vector<unsigned char> ciphertext = from_hex(ciphertext_hex);
    vector<unsigned char> aad = from_hex(aad_hex);

    size_t mlen_max = (ciphertext.size() > crypto_aead_xchacha20poly1305_ietf_ABYTES) ? (ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES) : 0;
    vector<unsigned char> plaintext(mlen_max);
    unsigned long long mlen = 0;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
        plaintext.data(), &mlen,
        NULL, ciphertext.data(), ciphertext.size(),
        aad.data(), aad.size(),
        nonce.data(), key.data()) != 0) {
        sodium_memzero(key.data(), key.size());
        throw runtime_error("Invalid password or data tampered");
    }

    string out(reinterpret_cast<char*>(plaintext.data()), mlen);

    sodium_memzero(key.data(), key.size());
    sodium_memzero(plaintext.data(), plaintext.size());

    return out;
}

// ------------------------- File format helpers -------------------------
// File layout:
// Line 1: account_salt_hex:verify_nonce_hex:verify_ciphertext_hex
// Line 2..N: per-entry lines: entry_salt_hex:nonce_hex:ciphertext_hex (blank line separator)
// Corrupted entries are stored as "00".

// ------------------------- Decrypt Entries ----------------------------- 
bool decrypt_all_entries(const string& master_password, const string& entry_salt, const string& nonce_hex, const string& ciphertext_hex, PasswordEntry& entry) {
    try {
        string entry_key_hex = derive_key_hex_from_password(master_password, entry_salt);
        string decrypted = decrypt_xchacha_hex_with_key(nonce_hex, ciphertext_hex, entry_key_hex, entry_salt);
        sodium_memzero((void*)entry_key_hex.data(), entry_key_hex.size());

        string expected = string(":D-tag=") + D_TAG;
        if (decrypted.size() < expected.size() || decrypted.substr(decrypted.size() - expected.size()) != expected) {
            entry = {"(CORRUPTED ENTRY)", "", "<d-tag mismatch>", true, entry_salt, nonce_hex, ciphertext_hex};
            return false;
        }

        string payload = decrypted.substr(0, decrypted.size() - expected.size());
        vector<string> parts;
        stringstream ss(payload);
        string f;
        while (getline(ss, f, ':')) parts.push_back(f);

        if (parts.size() != 3) {
            entry = {"(CORRUPTED ENTRY)", "", "<invalid payload format>", true, entry_salt, nonce_hex, ciphertext_hex};
            return false;
        }

        entry = {parts[0], parts[1], parts[2], false, entry_salt, nonce_hex, ciphertext_hex};
        return true;
    } catch (const exception& e) {
        entry = {"(CORRUPTED ENTRY)", "", string("<decrypt failed: ") + e.what() + ">", true, entry_salt, nonce_hex, ciphertext_hex};
        return false;
    }
}

// ------------------------- Save File  -------------------------
void save_all_entries_to_file(const string& master_password, vector<PasswordEntry>& entries) {
    const char* home_c = getenv("HOME");
    if (!home_c) throw runtime_error("HOME not set");
    string home_dir(home_c);
    string full_path = home_dir + "/" + DIRNAME + "/" + FILENAME;
    string tmp_path = full_path + ".tmp";

    ifstream check_file(full_path);
    if (!check_file) {
        throw runtime_error("System file missing");
    }

    // Read existing file
    ifstream in(full_path);
    string header;
    if (!getline(in, header)) {
        in.close();
        check_file.close();
        throw runtime_error("Empty or corrupted system file");
    }
    vector<string> existing_lines;
    string line;
    while (getline(in, line)) {
        if (!line.empty()) {
            existing_lines.push_back(line);
        }
    }
    in.close();
    check_file.close();

    // Write to temporary file
    ofstream out(tmp_path, ios::out | ios::trunc);
    if (!out) throw runtime_error("Unable to open temp file for writing");

    out << header << "\n\n";

    // Write entries
    size_t i = 0;
    for (; i < entries.size(); ++i) {
        if (entries[i].corrupted) {
            out << "00\n\n";
            continue;
        }
        
        if (!entries[i].ciphertext_hex.empty() && !entries[i].entry_salt_hex.empty() && !entries[i].nonce_hex.empty()) {
            out << entries[i].entry_salt_hex << ":" << entries[i].nonce_hex << ":" << entries[i].ciphertext_hex << "\n\n";
        } else {
            // Encrypt new or modified entries
            string entry_salt = generate_salt_hex();
            string entry_key_hex = derive_key_hex_from_password(master_password, entry_salt);
            string plaintext = entries[i].service + ":" + entries[i].username + ":" + entries[i].password + ":D-tag=" + D_TAG;
            string nonce_hex;
            string ciphertext_hex = encrypt_xchacha_hex_with_key(plaintext, entry_key_hex, entry_salt, nonce_hex);

            entries[i].entry_salt_hex = entry_salt;
            entries[i].nonce_hex = nonce_hex;
            entries[i].ciphertext_hex = ciphertext_hex;

            out << entry_salt << ":" << nonce_hex << ":" << ciphertext_hex << "\n\n";

            sodium_memzero((void*)entry_key_hex.data(), entry_key_hex.size());
        }
    }

    // Preserve remaining entries from the file
    for (; i < existing_lines.size(); ++i) {
        out << existing_lines[i] << "\n\n";
    }

    out.close();

    chmod(tmp_path.c_str(), S_IRUSR | S_IWUSR);
    if (rename(tmp_path.c_str(), full_path.c_str()) != 0) {
        unlink(tmp_path.c_str());
        throw runtime_error("Atomic rename failed");
    }
}

//------------------------ Load File ---------------------------

vector<PasswordEntry> load_entries_from_file_after_auth(const string& master_password, const string& full_path) {
    vector<PasswordEntry> entries;
    ifstream in(full_path);
    if (!in) throw runtime_error("Unable to open system file");

    string line;
    if (!getline(in, line)) {
        in.close();
        throw runtime_error("Empty system file");
    }

    while (getline(in, line)) {
        if (line.empty()) {
            continue;
        }
        if (line == "00") {
            entries.push_back({"(CORRUPTED ENTRY)", "", "<previously marked corrupted>", true, "", "", ""});
            continue;
        }

        size_t c1 = line.find(':');
        if (c1 == string::npos) {
            entries.push_back({"(CORRUPTED ENTRY)", "", "<malformed line: no colons>", true, "", "", ""});
            continue;
        }
        size_t c2 = line.find(':', c1 + 1);
        if (c2 == string::npos) {
            entries.push_back({"(CORRUPTED ENTRY)", "", "<malformed line: missing second colon>", true, "", "", ""});
            continue;
        }

        string entry_salt = line.substr(0, c1);
        string nonce_hex = line.substr(c1 + 1, c2 - (c1 + 1));
        string ciphertext_hex = line.substr(c2 + 1);

        if (entry_salt.empty() || nonce_hex.empty() || ciphertext_hex.empty()) {
            entries.push_back({"(CORRUPTED ENTRY)", "", "<empty salt, nonce, or ciphertext>", true, entry_salt, nonce_hex, ciphertext_hex});
            continue;
        }

        PasswordEntry entry;
        decrypt_all_entries(master_password, entry_salt, nonce_hex, ciphertext_hex, entry);
        entries.push_back(entry);
    }
    in.close();
    return entries;
}

// ------------------------- Hide Input  -------------------------
string getHiddenInput(const string& prompt) {
    cout <<YELLOW<<"[*]"<<RESET<< prompt;
    termios oldt, newt;
    string password;

    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    getline(cin, password);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    cout << endl;

    return password;
}

//------------------------ Add Password -------------------------- 
void addPass(vector<PasswordEntry>& entries, const string& master_password) {
    system("clear");
    cout << YELLOW <<"\n=================================================" << RESET << endl;
    cout << CYAN <<"                  Add Password" << RESET << endl;
    cout << YELLOW <<"=================================================" << RESET << endl;
     
        string service, username, password;
    cin.ignore(numeric_limits<streamsize>::max(), '\n');
    do {
        cout << YELLOW << "\n[*]" << RESET << " Enter Service: ";
        getline(cin, service);
        if (service.empty()) cout << RED << "[*]" << RESET << " Service cannot be empty.\n";
    } while (service.empty());

    do {
        cout << YELLOW << "[*]" << RESET << " Enter Username: ";
        getline(cin, username);
        if (username.empty()) cout << RED << "[*]" << RESET << " Username cannot be empty.\n";
    } while (username.empty());

    do {
        cout << YELLOW << "[*]" << RESET << " Enter Password: ";
        getline(cin, password);
        if (password.empty()) cout << RED << "[*]" << RESET << " Password cannot be empty.\n";
    } while (password.empty());

    PasswordEntry pe{service, username, password, false, "", "", ""};
    entries.push_back(pe);

    try {
        save_all_entries_to_file(master_password, entries);
        cout << GREEN << "\n[*]" << RESET << " Password added and saved." << endl;
    } catch (const exception& e) {
        cout << RED << "[*]" << RESET << " Failed to save: " << e.what() << RESET << endl;
    }

    sodium_memzero((void*)password.data(), password.size());   
}

//----------------------- View Passwords ------------------------
void viewPass(const vector<PasswordEntry>& entries) {
    cin.ignore(numeric_limits<streamsize>::max(), '\n');
    system("clear");
    cout << YELLOW <<"\n=================================================" << RESET << endl;
    cout << CYAN <<"                 Stored Passwords" << RESET << endl;
    cout << YELLOW <<"=================================================" << RESET << endl;

    if (entries.empty()) {
        cout <<GREEN<<"\n[*]"<<RESET<<" No entries stored." << endl;
        return;
    }

    for (size_t i = 0; i < entries.size(); ++i) {
        cout <<GREEN<< i+1<<"."<<RESET << " Service: " << entries[i].service << "\n"
             << "   Username: " << entries[i].username << "\n";
        if (entries[i].corrupted) {
            cout << "   Password: " << RED << "<CORRUPTED or TAMPERED ENTRY>" << RESET << "\n\n";
        } else {
            cout << "   Password: " << entries[i].password << "\n\n";
        }
    }
}

//-------------------- Edit Password --------------------------
void editPass(vector<PasswordEntry>& entries, const string& master_password) {

    cin.ignore(numeric_limits<streamsize>::max(), '\n');
    system("clear");
    cout << YELLOW <<"\n=================================================" << RESET << endl;
    cout << CYAN <<"                 Edit Passwords" << RESET << endl;
    cout << YELLOW <<"=================================================" << RESET << endl;

    if (entries.empty()) {
        cout <<GREEN<<"\n[*]"<<RESET<<" No entries stored." << endl;
        return;
    }

    for (size_t i = 0; i < entries.size(); ++i) {
        cout <<GREEN<< i+1<<"."<<RESET << " Service: " << entries[i].service << "\n"
             << "   Username: " << entries[i].username << "\n";
        if (entries[i].corrupted) {
            cout << "   Password: " << RED << "<CORRUPTED or TAMPERED ENTRY>" << RESET << "\n\n";
        } else {
            cout << "   Password: " << entries[i].password << "\n\n";
        }
    }
   
    cout << YELLOW << "\n[*]" << RESET << " Enter entry number to edit (0 to quit): ";
    int idx;    
    
    if (!(cin >> idx)) {
        cin.clear();
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        cout << RED << "[*]" << RESET << " Invalid input" << endl;
        return;
    }
    if (idx == 0) return; // Quit
    if (idx < 1 || idx > (int)entries.size()) {
        cout << RED << "[*]" << RESET << " Out of range" << endl;
        return;
    }

    cin.ignore(numeric_limits<streamsize>::max(), '\n');
    --idx;
    if (entries[idx].corrupted) {
        cout << RED << "[*]" << RESET << " Cannot edit a corrupted entry, Delete it!" << endl;
        return;
    }

    cout << YELLOW << "\n[*]" << RESET << " New Service (leave blank to keep): ";
    string s;
    getline(cin, s);
    if (!s.empty()) entries[idx].service = s;

    cout << YELLOW << "[*]" << RESET << " New Username (leave blank to keep): ";
    getline(cin, s);
    if (!s.empty()) entries[idx].username = s;

    cout << YELLOW << "[*]" << RESET << " New Password (leave blank to keep): ";
    getline(cin, s);
    if (!s.empty()) entries[idx].password = s;

    // Mark as modified by clearing cryptographic parameters
    entries[idx].entry_salt_hex = "";
    entries[idx].nonce_hex = "";
    entries[idx].ciphertext_hex = "";

    try {
        save_all_entries_to_file(master_password, entries);
        cout << GREEN << "\n[*]" << RESET << " Changes saved." << endl;
    } catch (const exception& e) {
        cout << RED << "\n[*]" << RESET << " Failed to save: " << e.what() << endl;
    }

}

//----------------------------- Delete Password Entry --------------------------
void deletePass(vector<PasswordEntry>& entries, const string& master_password) {
    cin.ignore(numeric_limits<streamsize>::max(), '\n');
    system("clear");
    cout << YELLOW <<"\n=================================================" << RESET << endl;
    cout << CYAN <<"                 Delete Passwords" << RESET << endl;
    cout << YELLOW <<"=================================================" << RESET << endl;

    if (entries.empty()) {
        cout <<GREEN<<"\n[*]"<<RESET<<" No entries stored." << endl;
        return;
    }

    for (size_t i = 0; i < entries.size(); ++i) {
        cout <<GREEN<< i+1<<"."<<RESET << " Service: " << entries[i].service << "\n"
             << "   Username: " << entries[i].username << "\n";
        if (entries[i].corrupted) {
            cout << "   Password: " << RED << "<CORRUPTED or TAMPERED ENTRY>" << RESET << "\n\n";
        } else {
            cout << "   Password: " << entries[i].password << "\n\n";
        }
    }
 
    cout << YELLOW << "\n[*]" << RESET << " Enter entry number to delete (0 to quit): ";
    int idx;
    if (!(cin >> idx)) {
        cin.clear();
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        cout << RED << "[*]" << RESET << " Invalid input"  << endl;
        return;
    }
    if (idx == 0) return; 
    if (idx < 1 || idx > (int)entries.size()) {
        cout << RED << "[*]" << RESET << " Out of range" << endl;
        return;
    }

    
    cout << YELLOW << "\n[*]" << RESET << " Are you sure you want to delete this entry? (y/n): ";
    char confirm;
    cin >> confirm;
    if (tolower(confirm) != 'y') {
        cout << GREEN << "[*]" << RESET << " Deletion cancelled." << endl;
         cin.ignore(numeric_limits<streamsize>::max(), '\n');
         return;
    }

    --idx;
    entries.erase(entries.begin() + idx);

    try {
        save_all_entries_to_file(master_password, entries);
        cout << GREEN << "\n[*]" << RESET << " Deleted." << endl;
        cin.ignore(numeric_limits<streamsize>::max(), '\n'); 
    } catch (const exception& e) {
        cout << RED << "\n[*]" << RESET << " Failed to save: " << e.what() << endl;
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
      }

}

// ------------------------- Change Master Password -------------------------
void change_master_password_flow(const string& full_path, const string& current_password, vector<PasswordEntry>& entries) {
    cin.ignore(numeric_limits<streamsize>::max(), '\n');

    system("clear");
    cout << YELLOW << "\n=================================================" << RESET << endl;
    cout << CYAN <<     "              Change Master Password" << RESET << endl;
    cout << YELLOW <<   "=================================================" << RESET << endl;

    ifstream in(full_path);
    if (!in) {
        cout << RED << "[*]"<<RESET<<" Unable to open system file"<< endl;
        return;
    }
    string header;
    if (!getline(in, header)) {
        in.close();
        cout << RED << "[*]"<<RESET<<" Empty system file" << endl;
        return;
    }
    in.close();

    size_t first_colon = header.find(':');
    if (first_colon == string::npos) {
        cout << RED << "[*]"<<RESET<<" Malformed header"  << endl;
        return;
    }
    size_t second_colon = header.find(':', first_colon + 1);
    if (second_colon == string::npos) {
        cout << RED << "[*]"<<RESET<<" Malformed header"  << endl;
        return;
    }

    string salt_hex = header.substr(0, first_colon);
    string verify_nonce_hex = header.substr(first_colon + 1, second_colon - (first_colon + 1));
    string verify_ciphertext_hex = header.substr(second_colon + 1);

    try {
        string derived = derive_key_hex_from_password(current_password, salt_hex);
        string decrypted = decrypt_xchacha_hex_with_key(verify_nonce_hex, verify_ciphertext_hex, derived, salt_hex);
        if (decrypted != D_TAG) {
            throw runtime_error("Verification tag mismatch");
        }
        sodium_memzero((void*)derived.data(), derived.size());
    } catch (const exception& e) {
        cout << RED << "[*]"<<RESET<<" Error verifying current password: " << e.what()  << endl;
        return;
    }

    bool iserror = false;
    string newpass;
    while (true) {
        if (iserror) cout << RED << "\n[*]"<<RESET<<" Minimum 12 chars, 1 upper, 1 lower, 1 digit, 1 special"  << endl;
        cout<<"\n"; 
        newpass = getHiddenInput(" Enter new: ");
        string confirm = getHiddenInput(" Confirm new: ");
        if (newpass != confirm) {
            cout << RED << "[*]"<<RESET<<" Passwords do not match. Try again." << endl;
            continue;
 
        }
          bool upper = false, lower = false, num = false, special = false, no_spaces = true;
        for (char c : newpass) {
            if (isupper(c)) upper = true;
            else if (islower(c)) lower = true;
            else if (isdigit(c)) num = true;
            else special = true;
            if (isspace(c)) no_spaces = false;
        }
        if (newpass.length() >= 12 && upper && lower && num && special && no_spaces) break;
        iserror = true;
    }

    string new_salt = generate_salt_hex();
    string new_key_hex;
    try {
        new_key_hex = derive_key_hex_from_password(newpass, new_salt);
    } catch (const exception& e) {
        cout << RED << "[*]"<<RESET<<" Failed to derive new key: " << e.what() << endl;
        sodium_memzero((void*)newpass.data(), newpass.size());
        return;
    }

    string new_nonce_hex;
    string new_ciphertext_hex = encrypt_xchacha_hex_with_key(D_TAG, new_key_hex, new_salt, new_nonce_hex);
    ofstream out(full_path, ios::out | ios::trunc);
    if (!out) {
        cout << RED << "[*]"<<RESET<<" Failed to create file" << endl;
        sodium_memzero((void*)newpass.data(), newpass.size());
        sodium_memzero((void*)new_key_hex.data(), new_key_hex.size());
        return;
    }
    out << new_salt << ":" << new_nonce_hex << ":" << new_ciphertext_hex << "\n\n";
    cout<<GREEN<<"\n[*]"<<RESET<<" Re-Encrypting all the Data..."<<endl;
    for (const auto& entry : entries) {
        if (entry.corrupted) {
            out << "00\n\n";
            continue;
        }

        string entry_salt = generate_salt_hex();
        string entry_key_hex = derive_key_hex_from_password(newpass, entry_salt);
        string plaintext = entry.service + ":" + entry.username + ":" + entry.password + ":D-tag=" + D_TAG;
        string nonce_hex;
        string ciphertext_hex = encrypt_xchacha_hex_with_key(plaintext, entry_key_hex, entry_salt, nonce_hex);

        out << entry_salt << ":" << nonce_hex << ":" << ciphertext_hex << "\n\n";

        sodium_memzero((void*)entry_key_hex.data(), entry_key_hex.size());
    }
    out.close();

    chmod(full_path.c_str(), S_IRUSR | S_IWUSR);

    cout << GREEN << "\n[*]"<<RESET<<" Master password changed and data re-encrypted."  << endl;

    sodium_memzero((void*)newpass.data(), newpass.size());
    sodium_memzero((void*)new_key_hex.data(), new_key_hex.size());
}

// ------------------------- Tips (rotating in RAM only) -------------------------
string get_rotating_tip() {
    static int tip_counter = 0;
    static const string tips[] = {
        "Tip: Don't tamper with the system.enc file \n or you will lose all your credentials.",
        "Tip: If your saved passwords entry is corrupted, \n then someone has tampered with the system.enc file.",
        "Tip: Encountering errors like: File not found, \n Malformed header or Empty System file, It means \n someone has altered the system.enc file!",
        "Tip: Use a passphrase or longer passwords \n for better security."
    };
    const int TIP_COUNT = 4;
    int idx = tip_counter % TIP_COUNT;
    string t = tips[idx];
    tip_counter = (tip_counter + 1) % TIP_COUNT;
    return t;
}

// ------------------------- Main interface -------------------------------------
void interface(const string& master_password, vector<PasswordEntry>& entries, const string& full_path) {
    int choice;

    system("clear");
    cout << YELLOW << "\n=================================================" << RESET << endl;
    cout << CYAN << "             Welcome to SilentVault" << RESET << endl;
    cout << CYAN << "         Your Ultimate Password Manager" << RESET << endl;
    cout << YELLOW << "=================================================" << RESET << endl;
    cout << "\n  Choose an option:" << endl;
    cout << "\n         1. Add New Password\n";
    cout << "         2. View Stored Passwords\n";
    cout << "         3. Edit Password\n";
    cout << "         4. Delete Password\n";
    cout << "         5. Change Master Password\n";
    cout << "         6. Clean Memory, Lock & Exit\n";
    cout << GREEN << "\n " << get_rotating_tip() << RESET << endl;
    cout << YELLOW << "\n=================================================" << RESET << endl;

    cout << YELLOW << "[*] " << RESET << "Enter your choice: ";
    cin >> choice;
    if (cin.fail()) {
        cout << RED << "[*]"<<RESET<<" Invalid input! Please enter a number." << endl;
        cin.clear();
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        interface(master_password, entries, full_path);
    }

    switch (choice) {
        case 1:
            addPass(entries, master_password);
            break;
        case 2:
            viewPass(entries);
            break;
        case 3:
            editPass(entries, master_password);
            break;
        case 4:
            deletePass(entries, master_password);
            break;
        case 5:
            change_master_password_flow(full_path, master_password, entries);
            break;
        case 6:
           system("clear");
            for (auto &e : entries) {
                sodium_memzero((void*)e.password.data(), e.password.size());
                sodium_memzero((void*)e.username.data(), e.username.size());
                sodium_memzero((void*)e.service.data(), e.service.size());
                sodium_memzero((void*)e.entry_salt_hex.data(), e.entry_salt_hex.size());
                sodium_memzero((void*)e.nonce_hex.data(), e.nonce_hex.size());
                sodium_memzero((void*)e.ciphertext_hex.data(), e.ciphertext_hex.size());
            }
            cout << GREEN << "\n [*]"<<RESET<<" Memory cleaned! & Exiting..."  << endl;
            exit(0);
            break;        
        default:
            cout << RED << "[*]"<<RESET<<" Invalid choice!";
            cin.ignore(numeric_limits<streamsize>::max(), '\n'); 
    }
    cout << YELLOW << "\n[*]"<<RESET<<" Press Enter to continue...";
    cin.ignore(numeric_limits<streamsize>::max(), '\n');
    interface(master_password, entries, full_path);
}

// ------------------------- Account creation -----------------------------
void create_account_flow(const string& full_path) {
   
    string master_pass;
    bool iserror = false;
    while (true) {
        if (iserror) cout << RED << "[*]"<<RESET<<" Minimum 12 chars, 1 upper, 1 lower, 1 digit, 1 special" <<endl;
        cout << CYAN << "\n\n       --- Create Your Master Password ---\n" << RESET << endl;
        master_pass = getHiddenInput(" Enter: ");
        string confirm = getHiddenInput(" Confirm: ");
        if (master_pass != confirm) {   

        cout << RED << "[*]"<<RESET<<" Passwords do not match. Try again." <<endl;
            continue;
        }
       
       bool upper = false, lower = false, num = false, special = false, no_spaces = true;
        for (char c : master_pass) {
            if (isupper(c)) upper = true;
            else if (islower(c)) lower = true;
            else if (isdigit(c)) num = true;
            else special = true;
            if (isspace(c)) no_spaces = false;
        }
        if (master_pass.length() >= 12 && upper && lower && num && special && no_spaces) break;
        iserror = true;
    }


     string salt_hex = generate_salt_hex();
    string key_hex;
    try {
        key_hex = derive_key_hex_from_password(master_pass, salt_hex);
    } catch (const exception& e) {
        cout << RED << "[*]"<<RESET<<" Failed to derive key: " << e.what()<< endl;
        sodium_memzero((void*)master_pass.data(), master_pass.size());
        return;
    }

    const char* home_c = getenv("HOME");
    if (!home_c) {
        cout << RED << "[*]"<<RESET<<" HOME not set" << endl;
        sodium_memzero((void*)master_pass.data(), master_pass.size());
        sodium_memzero((void*)key_hex.data(), key_hex.size());
        return;
    }
    string home_dir(home_c);
    string directory = home_dir + "/" + DIRNAME;
    if (mkdir(directory.c_str(), 0700) != 0 && errno != EEXIST) {
        cout << RED << "[*]"<<RESET<<" Failed to create directory " << endl;
        sodium_memzero((void*)master_pass.data(), master_pass.size());
        sodium_memzero((void*)key_hex.data(), key_hex.size());
        return;
    }

    string nonce_hex;
    string ciphertext_hex;
    try {
        ciphertext_hex = encrypt_xchacha_hex_with_key(D_TAG, key_hex, salt_hex, nonce_hex);
    } catch (const exception& e) {
        cout << RED << "[*]"<<RESET<<" Failed to encrypt verification tag: " << e.what() << endl;
        sodium_memzero((void*)master_pass.data(), master_pass.size());
        sodium_memzero((void*)key_hex.data(), key_hex.size());
        return;
    }

    ofstream out(full_path, ios::out | ios::trunc);
    if (!out) {
        cout << RED << "[*]"<<RESET<<" Failed to create file"<< endl;
        sodium_memzero((void*)master_pass.data(), master_pass.size());
        sodium_memzero((void*)key_hex.data(), key_hex.size());
        return;
    }
    out << salt_hex << ":" << nonce_hex << ":" << ciphertext_hex << "\n\n";
    out.close();

    chmod(full_path.c_str(), S_IRUSR | S_IWUSR);

    sodium_memzero((void*)master_pass.data(), master_pass.size());
    sodium_memzero((void*)key_hex.data(), key_hex.size());

    cout << GREEN << "[*]"<<RESET<<" Account created. Please login.";
}

//---------------------------------- Login -------------------------------------
void login_flow(const string& full_path) {
        cout<<"\n\n";
    string master_pass = getHiddenInput(" Enter master password: ");

    ifstream in(full_path);
    if (!in) {
        cout << RED << "[*]"<<RESET<<" Unable to open system file" << endl;
        sodium_memzero((void*)master_pass.data(), master_pass.size());
        return;
    }
    string header;
    if (!getline(in, header)) {
        in.close();
        cout << RED << "[*]"<<RESET<<" Empty system file" << endl;
        sodium_memzero((void*)master_pass.data(), master_pass.size());
        return;
    }
    in.close();

    size_t first_colon = header.find(':');
    if (first_colon == string::npos) {
        cout << RED << "[*]"<<RESET<<" Malformed header" << endl;
        sodium_memzero((void*)master_pass.data(), master_pass.size());
        return;
    }
    size_t second_colon = header.find(':', first_colon + 1);
    if (second_colon == string::npos) {
        cout << RED << "[*]"<<RESET<<" Malformed header" << endl;
        sodium_memzero((void*)master_pass.data(), master_pass.size());
        return;
    }

    string salt_hex = header.substr(0, first_colon);
    string verify_nonce_hex = header.substr(first_colon + 1, second_colon - (first_colon + 1));
    string verify_ciphertext_hex = header.substr(second_colon + 1);

    try {
        string candidate_key = derive_key_hex_from_password(master_pass, salt_hex);
        string decrypted = decrypt_xchacha_hex_with_key(verify_nonce_hex, verify_ciphertext_hex, candidate_key, salt_hex);
        sodium_memzero((void*)candidate_key.data(), candidate_key.size());

        if (decrypted != D_TAG) {
            cout << RED << "[*]"<<RESET<<" Incorrect Password" << endl;
            sodium_memzero((void*)master_pass.data(), master_pass.size());
            return;
        }
        cout<<GREEN<<"\n[*]"<<RESET<<" Authenticating..."<<endl;
        vector<PasswordEntry> entries = load_entries_from_file_after_auth(master_pass, full_path);
        interface(master_pass, entries, full_path);

        for (auto &e : entries) {
            sodium_memzero((void*)e.password.data(), e.password.size());
            sodium_memzero((void*)e.username.data(), e.username.size());
            sodium_memzero((void*)e.service.data(), e.service.size());
            sodium_memzero((void*)e.entry_salt_hex.data(), e.entry_salt_hex.size());
            sodium_memzero((void*)e.nonce_hex.data(), e.nonce_hex.size());
            sodium_memzero((void*)e.ciphertext_hex.data(), e.ciphertext_hex.size());
        }
        sodium_memzero((void*)master_pass.data(), master_pass.size());
    } catch (const exception& e) {
        cout << RED << "\n[*]"<<RESET<<" Login failed: " << e.what() << endl;
        sodium_memzero((void*)master_pass.data(), master_pass.size());
    }
}

// ------------------------- Main -------------------------
int main() {
   
    system("clear");
    cout << CYAN << R"(

 ____  _ _            _ __     __          _ _   
/ ___|(_) | ___ _ __ | |\ \   / /_ _ _   _| | |_ 
\___ \| | |/ _ \ '_ \| __\ \ / / _` | | | | | __|
 ___) | | |  __/ | | | |_ \ V / (_| | |_| | | |_ 
|____/|_|_|\___|_| |_|\__| \_/ \__,_|\__,_|_|\__|
)" << endl;
    cout << GREEN << "   Version:"<<RESET<<" 1.0" << endl;
    cout <<GREEN<< "   Author:"<<RESET<<" Muhammad Husnain Zargar" << endl;
    cout << YELLOW << "\n=================================================" << RESET << endl;

    const char* home_c = getenv("HOME");
    if (!home_c) {
        cout << RED <<"[*] HOME not set" << RESET << endl;
        return 1;
    }
    string home_dir(home_c);
    string directory = home_dir + "/" + DIRNAME;
    string full_path = directory + "/" + FILENAME;

    struct stat info;
    if (stat(directory.c_str(), &info) != 0 || !S_ISDIR(info.st_mode)) {
        create_account_flow(full_path);
    }

    ifstream infile(full_path);
    if (!infile) {
        cout << RED << "[*]"<<RESET<<" System file deleted, system locked." << endl;
        return 1;
    }
    infile.close();

    login_flow(full_path);

    return 0;
}
