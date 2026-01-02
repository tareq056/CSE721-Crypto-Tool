#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <limits>
#include <utility>

using namespace std;

// ====================== COMMON HELPERS ======================
int mod26(int x) {
    x %= 26;
    if (x < 0) x += 26;
    return x;
}

int gcd_int(int a, int b) {
    if (a < 0) a = -a;
    if (b < 0) b = -b;
    if (b == 0) return a;
    return gcd_int(b, a % b);
}

// Extended Euclid: returns gcd(a,b), finds x,y s.t. ax+by=gcd
int egcd(int a, int b, int &x, int &y) {
    if (b == 0) { x = 1; y = 0; return a; }
    int x1 = 0, y1 = 0;
    int g = egcd(b, a % b, x1, y1);
    x = y1;
    y = x1 - (a / b) * y1;
    return g;
}

// Modular inverse mod 26 (returns -1 if not exists)
int modInverse26(int a) {
    a = mod26(a);
    int x = 0, y = 0;
    int g = egcd(a, 26, x, y);
    if (g != 1) return -1;
    return mod26(x);
}

int readInt(const string &prompt) {
    while (true) {
        cout << prompt;
        int x;
        if (cin >> x) {
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            return x;
        }
        cin.clear();
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        cout << "Invalid number. Try again.\n";
    }
}

int readMenuChoice(const string &prompt, int lo, int hi) {
    while (true) {
        int c = readInt(prompt);
        if (c >= lo && c <= hi) return c;
        cout << "Invalid choice. Try again.\n";
    }
}

string readLine(const string &prompt) {
    cout << prompt;
    string s;
    getline(cin, s);
    return s;
}

// ============================================================
// ===================== HELPER FUNCTIONS ======================
// Clean functions: convert to lowercase or uppercase
string cleanLettersLower(const string &s) {
    string out;
    for (char ch : s) {
        if (isalpha((unsigned char)ch)) out += (char)tolower((unsigned char)ch);
    }
    return out;
}

string cleanLettersUpper(const string &s) {
    string out;
    for (char ch : s) {
        if (isalpha((unsigned char)ch)) out += (char)toupper((unsigned char)ch);
    }
    return out;
}

// ============================================================
// ====================== CAESAR CIPHER ========================
string caesarEncrypt(const string &plaintext, int shift) {
    shift = mod26(shift);
    string ciphertext;
    ciphertext.reserve(plaintext.size());

    for (char ch : plaintext) {
        if (isalpha((unsigned char)ch)) {
            char base = islower((unsigned char)ch) ? 'a' : 'A';
            ch = char((ch - base + shift) % 26 + base);
        }
        ciphertext += ch;
    }

    // Convert ciphertext to uppercase
    for (char &ch : ciphertext) {
        ch = toupper(ch);
    }

    return ciphertext;
}

string caesarDecrypt(const string &ciphertext, int shift) {
    string plaintext = caesarEncrypt(ciphertext, 26 - mod26(shift));

    // Convert decrypted text to lowercase
    for (char &ch : plaintext) {
        ch = tolower(ch);
    }

    return plaintext;
}

void caesarMenu() {
    while (true) {
        cout << "\n--- Caesar Cipher ---\n";
        cout << "1) Encrypt\n2) Decrypt\n3) Back\n";
        int choice = readMenuChoice("Choose: ", 1, 3);
        if (choice == 3) return;

        string text = readLine("Enter text: ");
        int shift = readInt("Enter shift value: ");

        if (choice == 1) cout << "Encrypted Text: " << caesarEncrypt(text, shift) << "\n";
        else             cout << "Decrypted Text: " << caesarDecrypt(text, shift) << "\n";
    }
}

// ====================== AFFINE CIPHER ========================
string affineEncrypt(const string &plaintext, int a, int b) {
    if (gcd_int(a, 26) != 1) return "Error: gcd(a,26) must be 1.";

    b = mod26(b);
    string ciphertext;
    ciphertext.reserve(plaintext.size());

    for (char ch : plaintext) {
        if (isalpha((unsigned char)ch)) {
            bool isUpper = isupper((unsigned char)ch);
            int x = tolower((unsigned char)ch) - 'a';
            int y = mod26(a * x + b);
            ciphertext += char((isUpper ? 'A' : 'a') + y);
        } else {
            ciphertext += ch;
        }
    }

    // Convert ciphertext to uppercase
    for (char &ch : ciphertext) {
        ch = toupper(ch);
    }

    return ciphertext;
}

string affineDecrypt(const string &ciphertext, int a, int b) {
    if (gcd_int(a, 26) != 1) return "Error: gcd(a,26) must be 1.";

    int a_inv = modInverse26(a);
    if (a_inv == -1) return "Error: modular inverse does not exist.";

    b = mod26(b);
    string plaintext;
    plaintext.reserve(ciphertext.size());

    for (char ch : ciphertext) {
        if (isalpha((unsigned char)ch)) {
            bool isUpper = isupper((unsigned char)ch);
            int y = tolower((unsigned char)ch) - 'a';
            int x = mod26(a_inv * (y - b));
            plaintext += char((isUpper ? 'A' : 'a') + x);
        } else {
            plaintext += ch;
        }
    }

    // Convert decrypted text to lowercase
    for (char &ch : plaintext) {
        ch = tolower(ch);
    }

    return plaintext;
}

void affineMenu() {
    while (true) {
        cout << "\n--- Affine Cipher ---\n";
        cout << "1) Encrypt\n2) Decrypt\n3) Back\n";
        int choice = readMenuChoice("Choose: ", 1, 3);
        if (choice == 3) return;

        string text = readLine("Enter text: ");
        int a = readInt("Enter key a: ");
        int b = readInt("Enter key b: ");

        if (choice == 1) cout << "Encrypted Text: " << affineEncrypt(text, a, b) << "\n";
        else             cout << "Decrypted Text: " << affineDecrypt(text, a, b) << "\n";
    }
}

// ===================== PLAYFAIR CIPHER =======================
static inline char pf_normChar(char ch) {
    ch = (char)tolower((unsigned char)ch);
    if (ch == 'j') ch = 'i';
    return ch;
}

static string pf_normalizeKey(const string &key) {
    vector<bool> used(26, false);
    used['j' - 'a'] = true; // omit j

    string out;
    for (char ch : key) {
        if (!isalpha((unsigned char)ch)) continue;
        ch = pf_normChar(ch);
        int idx = ch - 'a';
        if (!used[idx]) {
            used[idx] = true;
            out.push_back(ch);
        }
    }

    for (char ch = 'a'; ch <= 'z'; ch++) {
        if (ch == 'j') continue;
        int idx = ch - 'a';
        if (!used[idx]) {
            used[idx] = true;
            out.push_back(ch);
        }
    }
    return out; // 25
}

static void pf_buildMatrix(const string &key, char mat[5][5], pair<int,int> pos[26]) {
    string k = pf_normalizeKey(key);
    int p = 0;
    for (int r = 0; r < 5; r++) {
        for (int c = 0; c < 5; c++) {
            mat[r][c] = k[p++];
            pos[mat[r][c] - 'a'] = {r, c};
        }
    }
    pos['j' - 'a'] = pos['i' - 'a'];
}

static string pf_preparePlaintext(const string &plaintext) {
    string s;
    for (char ch : plaintext) {
        if (isalpha((unsigned char)ch)) s.push_back(pf_normChar(ch));
    }

    string out;
    for (size_t i = 0; i < s.size();) {
        char a = s[i];
        char b = (i + 1 < s.size()) ? s[i + 1] : 'x';

        if (a == b) { out.push_back(a); out.push_back('x'); i += 1; }
        else        { out.push_back(a); out.push_back(b);  i += 2; }
    }

    if (out.size() % 2 != 0) out.push_back('x');
    return out;
}

string playfairEncrypt(const string &plaintext, const string &key) {
    char mat[5][5];
    pair<int,int> pos[26];
    pf_buildMatrix(key, mat, pos);

    string pt = pf_preparePlaintext(plaintext);
    string ct;
    ct.reserve(pt.size());

    for (size_t i = 0; i < pt.size(); i += 2) {
        char a = pt[i], b = pt[i + 1];
        auto [r1, c1] = pos[a - 'a'];
        auto [r2, c2] = pos[b - 'a'];

        if (r1 == r2) {
            ct.push_back(mat[r1][(c1 + 1) % 5]);
            ct.push_back(mat[r2][(c2 + 1) % 5]);
        } else if (c1 == c2) {
            ct.push_back(mat[(r1 + 1) % 5][c1]);
            ct.push_back(mat[(r2 + 1) % 5][c2]);
        } else {
            ct.push_back(mat[r1][c2]);
            ct.push_back(mat[r2][c1]);
        }
    }

    // Convert ciphertext to uppercase
    for (char &ch : ct) ch = toupper((unsigned char)ch);
    return ct;
}

string playfairDecrypt(const string &ciphertext, const string &key) {
    char mat[5][5];
    pair<int,int> pos[26];
    pf_buildMatrix(key, mat, pos);

    string ct;
    for (char ch : ciphertext) {
        if (isalpha((unsigned char)ch)) ct.push_back(pf_normChar(ch));
    }
    if (ct.size() % 2 != 0) ct.push_back('x'); // safety

    string pt;
    pt.reserve(ct.size());

    for (size_t i = 0; i < ct.size(); i += 2) {
        char a = ct[i], b = ct[i + 1];
        auto [r1, c1] = pos[a - 'a'];
        auto [r2, c2] = pos[b - 'a'];

        if (r1 == r2) {
            pt.push_back(mat[r1][(c1 + 4) % 5]);
            pt.push_back(mat[r2][(c2 + 4) % 5]);
        } else if (c1 == c2) {
            pt.push_back(mat[(r1 + 4) % 5][c1]);
            pt.push_back(mat[(r2 + 4) % 5][c2]);
        } else {
            pt.push_back(mat[r1][c2]);
            pt.push_back(mat[r2][c1]);
        }
    }
    return pt; // lowercase letters only
}

void playfairMenu() {
    while (true) {
        cout << "\n--- Playfair Cipher ---\n";
        cout << "1) Encrypt\n2) Decrypt\n3) Back\n";
        int choice = readMenuChoice("Choose: ", 1, 3);
        if (choice == 3) return;

        string key = readLine("Enter key: ");
        string text = readLine(choice == 1 ? "Enter plaintext: " : "Enter ciphertext: ");

        if (choice == 1) {
            string ct = playfairEncrypt(text, key);
            cout << "Ciphertext (no spaces): " << ct << "\n";
            cout << "Ciphertext (digraphs): ";
            for (size_t i = 0; i < ct.size(); i += 2) {
                cout << ct[i] << ct[i + 1];
                if (i + 2 < ct.size()) cout << " ";
            }
            cout << "\n";
        } else {
            cout << "Plaintext: " << playfairDecrypt(text, key) << "\n";
        }
    }
}

// ============================================================
// ======================= HILL CIPHER 2x2 ======================
// Encrypts plaintext in lowercase and produces uppercase ciphertext
bool invertKey2x2(const int key[2][2], int invKey[2][2]) {
    int a = mod26(key[0][0]);
    int b = mod26(key[0][1]);
    int c = mod26(key[1][0]);
    int d = mod26(key[1][1]);

    int det = mod26(a * d - b * c);
    if (gcd_int(det, 26) != 1) return false;

    int detInv = modInverse26(det);
    if (detInv == -1) return false;

    invKey[0][0] = mod26(d * detInv);
    invKey[0][1] = mod26(-b * detInv);
    invKey[1][0] = mod26(-c * detInv);
    invKey[1][1] = mod26(a * detInv);
    return true;
}

string hillEncrypt2x2(const string &plaintextRaw, const int key[2][2]) {
    int dummyInv[2][2];
    if (!invertKey2x2(key, dummyInv)) return "Error: key matrix is not invertible modulo 26.";

    string pt = cleanLettersLower(plaintextRaw);
    if (pt.empty()) return "";

    if (pt.size() % 2 != 0) pt += 'x';

    string ct;
    ct.reserve(pt.size());

    for (size_t i = 0; i < pt.size(); i += 2) {
        int p1 = pt[i] - 'a';
        int p2 = pt[i + 1] - 'a';

        int c1 = mod26(key[0][0] * p1 + key[0][1] * p2);
        int c2 = mod26(key[1][0] * p1 + key[1][1] * p2);

        ct += char('A' + c1);  // Ensure uppercase
        ct += char('A' + c2);  // Ensure uppercase
    }

    return ct;
}

string hillDecrypt2x2(const string &ciphertextRaw, const int key[2][2]) {
    int invKey[2][2];
    if (!invertKey2x2(key, invKey)) return "Error: key matrix is not invertible modulo 26.";

    string ct = cleanLettersUpper(ciphertextRaw);
    if (ct.empty()) return "";

    if (ct.size() % 2 != 0) return "Error: ciphertext length must be even for 2x2 Hill cipher.";

    string pt;
    pt.reserve(ct.size());

    for (size_t i = 0; i < ct.size(); i += 2) {
        int c1 = ct[i] - 'A';
        int c2 = ct[i + 1] - 'A';

        int p1 = mod26(invKey[0][0] * c1 + invKey[0][1] * c2);
        int p2 = mod26(invKey[1][0] * c1 + invKey[1][1] * c2);

        pt += char('a' + p1);
        pt += char('a' + p2);
    }
    return pt;
}

void hillMenu() {
    while (true) {
        cout << "\n--- Hill Cipher (2x2) ---\n";
        cout << "1) Encrypt\n2) Decrypt\n3) Back\n";
        int choice = readMenuChoice("Choose: ", 1, 3);
        if (choice == 3) return;

        string text = readLine(choice == 1 ? "Enter plaintext: " : "Enter ciphertext: ");

        cout << "Enter 2x2 key matrix (row-wise, 4 integers): ";
        int key[2][2];
        while (!(cin >> key[0][0] >> key[0][1] >> key[1][0] >> key[1][1])) {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cout << "Invalid key input. Enter 4 integers: ";
        }
        cin.ignore(numeric_limits<streamsize>::max(), '\n');

        // normalize key values mod 26
        key[0][0] = mod26(key[0][0]);
        key[0][1] = mod26(key[0][1]);
        key[1][0] = mod26(key[1][0]);
        key[1][1] = mod26(key[1][1]);

        if (choice == 1) cout << "Encrypted Text: " << hillEncrypt2x2(text, key) << "\n";
        else             cout << "Decrypted Text: " << hillDecrypt2x2(text, key) << "\n";
    }
}

// ============================================================
// ============================== MAIN ==========================
int main() {
    while (true) {
        cout << "\n========== Crypto Tool (Part 1) ==========\n";
        cout << "1) Caesar Cipher\n";
        cout << "2) Affine Cipher\n";
        cout << "3) Playfair Cipher\n";
        cout << "4) Hill Cipher (2x2)\n";
        cout << "5) Exit\n";

        int choice = readMenuChoice("Select a cipher: ", 1, 5);
        if (choice == 5) {
            cout << "Exiting...\n";
            break;
        }

        switch (choice) {
            case 1: caesarMenu(); break;
            case 2: affineMenu(); break;
            case 3: playfairMenu(); break;
            case 4: hillMenu(); break;
            default: break;
        }
    }
    return 0;
}
