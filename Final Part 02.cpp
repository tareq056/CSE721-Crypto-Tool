#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <limits>
#include <utility>

using namespace std;

// ===================== Math Helpers =====================
int mod26(int x) {
    x %= 26;
    if (x < 0) x += 26;
    return x;
}

int gcd_int(int a, int b)
{
    if (a < 0) a = -a;
    if (b < 0) b = -b;
    if (b == 0) return a;
    return gcd_int(b, a % b);
}

// Extended Euclid: ax + by = gcd(a,b)
int egcd(int a, int b, int &x, int &y) {
    if (b == 0) { x = 1; y = 0; return a; }
    int x1 = 0, y1 = 0;
    int g = egcd(b, a % b, x1, y1);
    x = y1;
    y = x1 - (a / b) * y1;
    return g;
}

int modInverse26(int a) {
    a = mod26(a);
    int x = 0, y = 0;
    int g = egcd(a, 26, x, y);
    if (g != 1) return -1;
    return mod26(x);
}

// ===================== Text Helpers =====================
string lettersOnlyUpper(const string &s) {
    string out;
    for (char ch : s) {
        if (isalpha((unsigned char)ch)) out += (char)toupper((unsigned char)ch);
    }
    return out;
}

// Convert "ABCD..." into digraph vectors: [(A,B), (C,D), ...] where A=0..25
vector<pair<int,int>> toDigraphs(const string &upperEven) {
    vector<pair<int,int>> v;
    for (size_t i = 0; i + 1 < upperEven.size(); i += 2) {
        int x = upperEven[i] - 'A';
        int y = upperEven[i + 1] - 'A';
        v.push_back({x, y});
    }
    return v;
}

// ===================== Hill (2x2) Core =====================
// Treat each digraph as a ROW vector P = (x, y)
// Encryption: C = P * K (mod 26)  [Row-vector form]
pair<int,int> hillApplyRow(const int K[2][2], pair<int,int> p) {
    int x = p.first, y = p.second;

    // (x, y) * [ k00 k01 ] = ( x*k00 + y*k10 , x*k01 + y*k11 )
    //         [ k10 k11 ]
    int c1 = mod26(x * K[0][0] + y * K[1][0]);
    int c2 = mod26(x * K[0][1] + y * K[1][1]);
    return {c1, c2};
}

bool invert2x2mod26(const int M[2][2], int invM[2][2]) {
    int a = mod26(M[0][0]);
    int b = mod26(M[0][1]);
    int c = mod26(M[1][0]);
    int d = mod26(M[1][1]);

    int det = mod26(a * d - b * c);
    if (gcd_int(det, 26) != 1) return false;

    int detInv = modInverse26(det);
    if (detInv == -1) return false;

    // inv = detInv * [ d  -b
    //                 -c   a ] (mod 26)
    invM[0][0] = mod26(d * detInv);
    invM[0][1] = mod26(-b * detInv);
    invM[1][0] = mod26(-c * detInv);
    invM[1][1] = mod26(a * detInv);
    return true;
}

// 2x2 matrix multiply: R = A * B (mod 26)
void multiply2x2(const int A[2][2], const int B[2][2], int R[2][2]) {
    R[0][0] = mod26(A[0][0] * B[0][0] + A[0][1] * B[1][0]);
    R[0][1] = mod26(A[0][0] * B[0][1] + A[0][1] * B[1][1]);
    R[1][0] = mod26(A[1][0] * B[0][0] + A[1][1] * B[1][0]);
    R[1][1] = mod26(A[1][0] * B[0][1] + A[1][1] * B[1][1]);
}

// Verify K against all known digraphs
bool verifyKeyRow(const int K[2][2],
                  const vector<pair<int,int>> &P,
                  const vector<pair<int,int>> &C) {
    if (P.size() != C.size()) return false;
    for (size_t i = 0; i < P.size(); i++) {
        auto got = hillApplyRow(K, P[i]);
        if (got.first != C[i].first || got.second != C[i].second) return false;
    }
    return true;
}

// Recover 2x2 Hill key from known plaintext/ciphertext (same length, >=4 letters)
// build P (2x2) from two plaintext digraphs as ROWS, same for C,
// then K = P^{-1} * C (mod 26).
bool recoverHillKey2x2(const string &knownPlainRaw,
                           const string &knownCipherRaw,
                           int Kout[2][2]) {
    string Ptxt = lettersOnlyUpper(knownPlainRaw);
    string Ctxt = lettersOnlyUpper(knownCipherRaw);

    if (Ptxt.size() != Ctxt.size()) return false;
    if (Ptxt.size() < 4) return false;

    // enforce even length by truncating last char if odd
    if (Ptxt.size() % 2 != 0) {
        Ptxt.pop_back();
        Ctxt.pop_back();
    }

    auto P = toDigraphs(Ptxt);
    auto C = toDigraphs(Ctxt);
    if (P.size() < 2) return false;

    // Try any 2 digraphs (i, j) to build an invertible P-matrix (mod 26)
    for (size_t i = 0; i < P.size(); i++) {
        for (size_t j = i + 1; j < P.size(); j++) {

            // Pmat rows are plaintext digraphs
            int Pmat[2][2] = {
                { P[i].first,  P[i].second },
                { P[j].first,  P[j].second }
            };

            int invP[2][2];
            if (!invert2x2mod26(Pmat, invP)) continue;

            // Cmat rows are ciphertext digraphs
            int Cmat[2][2] = {
                { C[i].first,  C[i].second },
                { C[j].first,  C[j].second }
            };

            // K = inv(P) * C  (mod 26)
            int K[2][2];
            multiply2x2(invP, Cmat, K);

            if (verifyKeyRow(K, P, C)) {
                Kout[0][0] = K[0][0]; Kout[0][1] = K[0][1];
                Kout[1][0] = K[1][0]; Kout[1][1] = K[1][1];
                return true;
            }
        }
    }
    return false;
}

// Decrypt ciphertext using recovered key
// C = P*K  =>  P = C*K^{-1}
string hillDecryptWithKeyRow(const string &cipherRaw, const int K[2][2]) {
    int invK[2][2];
    if (!invert2x2mod26(K, invK)) return "Error: recovered key is not invertible (unexpected).";

    string Ctxt = lettersOnlyUpper(cipherRaw);
    if (Ctxt.empty()) return "";
    if (Ctxt.size() % 2 != 0) return "Error: ciphertext length must be even (2x2 Hill).";

    auto C = toDigraphs(Ctxt);
    string pt;
    pt.reserve(Ctxt.size());

    for (auto dig : C) {
        int c1 = dig.first, c2 = dig.second;

        // (c1, c2) * invK
        int p1 = mod26(c1 * invK[0][0] + c2 * invK[1][0]);
        int p2 = mod26(c1 * invK[0][1] + c2 * invK[1][1]);

        pt += char('a' + p1);
        pt += char('a' + p2);
    }
    return pt;
}

// Encrypt plaintext using recovered key (quick check): C = P*K
string hillEncryptWithKeyRow(const string &plainRaw, const int K[2][2]) {
    string Ptxt = lettersOnlyUpper(plainRaw);
    if (Ptxt.empty()) return "";

    if (Ptxt.size() % 2 != 0) Ptxt += 'X';

    auto P = toDigraphs(Ptxt);
    string ct;
    ct.reserve(Ptxt.size());

    for (auto dig : P) {
        auto out = hillApplyRow(K, dig);
        ct += char('A' + out.first);
        ct += char('A' + out.second);
    }
    return ct;
}

// ===================== UI Helpers =====================
int readMenuChoice(const string &prompt, int lo, int hi) {
    while (true) {
        cout << prompt;
        int c;
        if (cin >> c) {
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            if (c >= lo && c <= hi) return c;
        } else {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
        }
        cout << "Invalid choice. Try again.\n";
    }
}

string readLine(const string &prompt) {
    cout << prompt;
    string s;
    getline(cin, s);
    return s;
}

void printKeyMatrix(const int K[2][2]) {
    cout << "Recovered Hill Cipher Key Matrix\n";
    cout << K[0][0] << " " << K[0][1] << "\n";
    cout << K[1][0] << " " << K[1][1] << "\n";
}

// ===================== MAIN (Part 2 Tool) =====================
int main() {
    bool hasKey = false;
    int K[2][2] = { {0,0},{0,0} };

    while (true) {
        cout << "\n=== Part 2: Hill Cipher Known-Plaintext Cracker ===\n";
        cout << "1) Recover Key (Known Plaintext Attack)\n";
        cout << "2) Decrypt Ciphertext using Recovered Key\n";
        cout << "3) Encrypt Plaintext using Recovered Key (Verify)\n";
        cout << "4) Exit\n";

        int choice = readMenuChoice("Choose: ", 1, 4);
        if (choice == 4) {
            cout << "Exiting...\n";
            break;
        }

        if (choice == 1) {
            string kp = readLine("Enter known plaintext: ");
            string kc = readLine("Enter corresponding known ciphertext: ");

            int recovered[2][2];
            if (!recoverHillKey2x2(kp, kc, recovered)) {
                cout << "Failed to recover key.\n";
                cout << "Make sure:\n";
                cout << "- plaintext and ciphertext have SAME number of letters (spaces/punct ignored)\n";
                cout << "- at least 4 letters are provided\n";
                cout << "- some 2-digraph plaintext matrix is invertible mod 26 (provide longer known text if needed)\n";
            } else {
                K[0][0] = recovered[0][0]; K[0][1] = recovered[0][1];
                K[1][0] = recovered[1][0]; K[1][1] = recovered[1][1];
                hasKey = true;

                printKeyMatrix(K);

                // quick verification: encrypt known plaintext and show
                string check = hillEncryptWithKeyRow(kp, K);
                cout << "Check (encrypt plaintext =>): " << check << "\n";
            }
        }
        else if (choice == 2) {
            if (!hasKey) {
                cout << "No key recovered yet. Use option (1) first.\n";
                continue;
            }
            string ct = readLine("Enter ciphertext to decrypt: ");
            cout << "Decrypted Text: " << hillDecryptWithKeyRow(ct, K) << "\n";
        }
        else if (choice == 3) {
            if (!hasKey) {
                cout << "No key recovered yet. Use option (1) first.\n";
                continue;
            }
            string pt = readLine("Enter plaintext to encrypt: ");
            cout << "Encrypted Text: " << hillEncryptWithKeyRow(pt, K) << "\n";
        }
    }

    return 0;
}
