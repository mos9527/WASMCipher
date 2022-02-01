/**
 * mos9527's Toy Cipher
 * 
 * Implements CBC & ECB stream cipherer, with error checking and more ;)
*/
#include <vector>
#include <iostream>
#include <string.h>
#include <iomanip>
#include <stdexcept>
#include <math.h>
typedef unsigned char uchar;
typedef std::basic_string<unsigned char> ustring;
/* Generated with utils/permutate.py */
const char BASE85[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+-;<=>?@^_`{|}~";
const char BASE64[] = "MOS4UEFGHJ/klpq9527LNPQRrtuvdefhwxyz0is1368KComIngTV+WABDXYZabcjfoRax*hUuvjiojasTYYou";
/* Generated with utils/invbox.py */
const uchar SBOX[] = {65, 36, 54, 31, 208, 109, 108, 56, 127, 53, 248, 86, 181, 21, 67, 0, 114, 178, 209, 176, 196, 112, 68, 106, 224, 214, 33, 105, 38, 189, 1, 90, 150, 192, 13, 129, 70, 246, 174, 182, 236, 9, 72, 135, 201, 213, 148, 226, 187, 147, 144, 97, 111, 169, 245, 134, 141, 46, 190, 188, 253, 107, 99, 158, 6, 180, 234, 113, 76, 92, 30, 167, 45, 103, 7, 37, 5, 35, 60, 225, 151, 119, 14, 220, 250, 120, 24, 238, 82, 49, 66, 179, 200, 211, 94, 183, 58, 249, 132, 50, 143, 122, 175, 69, 163, 233, 128, 23, 79, 212, 191, 15, 146, 91, 83, 27, 227, 130, 115, 102, 228, 34, 252, 202, 40, 243, 195, 164, 223, 89, 121, 16, 96, 140, 237, 207, 142, 22, 123, 118, 48, 240, 20, 81, 168, 12, 165, 51, 124, 172, 8, 32, 241, 206, 149, 29, 161, 85, 64, 162, 173, 232, 19, 185, 152, 100, 160, 153, 52, 197, 184, 17, 75, 170, 216, 57, 11, 63, 139, 159, 199, 71, 255, 198, 155, 42, 104, 55, 251, 25, 77, 131, 247, 215, 244, 84, 43, 74, 4, 62, 219, 194, 235, 186, 78, 10, 87, 166, 117, 110, 116, 231, 204, 133, 98, 230, 44, 18, 193, 59, 93, 2, 138, 3, 156, 61, 80, 125, 217, 145, 222, 73, 177, 28, 239, 88, 101, 254, 95, 47, 136, 137, 210, 39, 26, 218, 157, 171, 126, 205, 154, 242, 221, 229, 203, 41};
/* Generated with utils/crc_table_gen.py 0xA833982B (CRC-32D polynomial)*/
const unsigned long crc32_table[] = {
    0x00000000,0xf6dd1a53,0x4589ac8d,0xb354b6de,0x8b13591a,0x7dce4349,0xce9af597,0x3847efc4,0xbe152a1f,0x48c8304c,0xfb9c8692,0x0d419cc1,0x35067305,0xc3db6956,0x708fdf88,0x8652c5db, 
    0x2bddd04f,0xdd00ca1c,0x6e547cc2,0x98896691,0xa0ce8955,0x56139306,0xe54725d8,0x139a3f8b,0x95c8fa50,0x6315e003,0xd04156dd,0x269c4c8e,0x1edba34a,0xe806b919,0x5b520fc7,0xad8f1594, 
    0x57bba09e,0xa166bacd,0x12320c13,0xe4ef1640,0xdca8f984,0x2a75e3d7,0x99215509,0x6ffc4f5a,0xe9ae8a81,0x1f7390d2,0xac27260c,0x5afa3c5f,0x62bdd39b,0x9460c9c8,0x27347f16,0xd1e96545, 
    0x7c6670d1,0x8abb6a82,0x39efdc5c,0xcf32c60f,0xf77529cb,0x01a83398,0xb2fc8546,0x44219f15,0xc2735ace,0x34ae409d,0x87faf643,0x7127ec10,0x496003d4,0xbfbd1987,0x0ce9af59,0xfa34b50a, 
    0xaf77413c,0x59aa5b6f,0xeafeedb1,0x1c23f7e2,0x24641826,0xd2b90275,0x61edb4ab,0x9730aef8,0x11626b23,0xe7bf7170,0x54ebc7ae,0xa236ddfd,0x9a713239,0x6cac286a,0xdff89eb4,0x292584e7, 
    0x84aa9173,0x72778b20,0xc1233dfe,0x37fe27ad,0x0fb9c869,0xf964d23a,0x4a3064e4,0xbced7eb7,0x3abfbb6c,0xcc62a13f,0x7f3617e1,0x89eb0db2,0xb1ace276,0x4771f825,0xf4254efb,0x02f854a8, 
    0xf8cce1a2,0x0e11fbf1,0xbd454d2f,0x4b98577c,0x73dfb8b8,0x8502a2eb,0x36561435,0xc08b0e66,0x46d9cbbd,0xb004d1ee,0x03506730,0xf58d7d63,0xcdca92a7,0x3b1788f4,0x88433e2a,0x7e9e2479, 
    0xd31131ed,0x25cc2bbe,0x96989d60,0x60458733,0x580268f7,0xaedf72a4,0x1d8bc47a,0xeb56de29,0x6d041bf2,0x9bd901a1,0x288db77f,0xde50ad2c,0xe61742e8,0x10ca58bb,0xa39eee65,0x5543f436, 
    0xf6dd1a53,0x4589ac8d,0xb354b6de,0x8b13591a,0x7dce4349,0xce9af597,0x3847efc4,0xbe152a1f,0x48c8304c,0xfb9c8692,0x0d419cc1,0x35067305,0xc3db6956,0x708fdf88,0x8652c5db,0xd419cc15, 
    0xdd00ca1c,0x6e547cc2,0x98896691,0xa0ce8955,0x56139306,0xe54725d8,0x139a3f8b,0x95c8fa50,0x6315e003,0xd04156dd,0x269c4c8e,0x1edba34a,0xe806b919,0x5b520fc7,0xad8f1594,0xffc41c5a, 
    0xa166bacd,0x12320c13,0xe4ef1640,0xdca8f984,0x2a75e3d7,0x99215509,0x6ffc4f5a,0xe9ae8a81,0x1f7390d2,0xac27260c,0x5afa3c5f,0x62bdd39b,0x9460c9c8,0x27347f16,0xd1e96545,0x83a26c8b, 
    0x8abb6a82,0x39efdc5c,0xcf32c60f,0xf77529cb,0x01a83398,0xb2fc8546,0x44219f15,0xc2735ace,0x34ae409d,0x87faf643,0x7127ec10,0x496003d4,0xbfbd1987,0x0ce9af59,0xfa34b50a,0xa87fbcc4, 
    0x59aa5b6f,0xeafeedb1,0x1c23f7e2,0x24641826,0xd2b90275,0x61edb4ab,0x9730aef8,0x11626b23,0xe7bf7170,0x54ebc7ae,0xa236ddfd,0x9a713239,0x6cac286a,0xdff89eb4,0x292584e7,0x7b6e8d29, 
    0x72778b20,0xc1233dfe,0x37fe27ad,0x0fb9c869,0xf964d23a,0x4a3064e4,0xbced7eb7,0x3abfbb6c,0xcc62a13f,0x7f3617e1,0x89eb0db2,0xb1ace276,0x4771f825,0xf4254efb,0x02f854a8,0x50b35d66, 
    0x0e11fbf1,0xbd454d2f,0x4b98577c,0x73dfb8b8,0x8502a2eb,0x36561435,0xc08b0e66,0x46d9cbbd,0xb004d1ee,0x03506730,0xf58d7d63,0xcdca92a7,0x3b1788f4,0x88433e2a,0x7e9e2479,0x2cd52db7, 
    0x25cc2bbe,0x96989d60,0x60458733,0x580268f7,0xaedf72a4,0x1d8bc47a,0xeb56de29,0x6d041bf2,0x9bd901a1,0x288db77f,0xde50ad2c,0xe61742e8,0x10ca58bb,0xa39eee65,0x5543f436,0x0708fdf8, 
};
const uchar padchar = '/';
const int   fencePeroid = 4;
class Codec{
    public:
        virtual std::string encode(ustring &in){
            return std::string((char*)in.c_str());
        }
        virtual ustring decode(std::string &in){
            return ustring((uchar*)in.c_str());
        }
        std::string fence(std::string &in,int period){
            std::string s;            
            int p = ceil((float)in.length() / (float)period);
            for(int i=0;i < in.length();i++){
                int r = period * (i % p) + i / p;
                std::cout << std::setw(2) << r << ' ';
                s.push_back(in[r]);                    
            }            
            return s;
        }    
        std::string defence(std::string &in,int period){
            std::string s;
            int p = ceil((float)in.length() / (float)period);
            for(int i=0;i < in.length();i++){
                int r = (i / period) + (i - (i / period) * period) * p;                
                std::cout << std::setw(2) << r << ' ';
                s.push_back(in[r]);
            }            
            return s;
        }      
    private:
        char const *base;        
        std::vector<int> *base_inv;
};
/* Simple BASE85 encoder / decoder */
class B85codec : public Codec
{
    #define N85_4 52200625
    #define N85_3 614125
    #define N85_2 7225
    #define N85   85
    public:
        B85codec(){
            base = BASE85;
            std::vector<int> inv(256, 0); for (int i = 0; i < 85; i++) inv[base[i]] = i;
            base_inv = inv;
        }
        std::string encode(ustring &in){	
            int i=0;
            std::string out;
            auto add = [&](uint32_t v){ 
                uint32_t t = v / N85_4; v -= t * N85_4;
                out.push_back(base[t]);        
                t = v / N85_3; v -= t  * N85_3;                
                out.push_back(base[t]);        
                t = v / N85_2; v -= t  * N85_2;         
                out.push_back(base[t]);        
                t = v / N85; v -= t  * N85;  
                out.push_back(base[t]);        
                out.push_back(base[v]);        
            };
            auto make_int = [&](uchar *f){
                uint32_t v = *f;                 
                v <<= 8; v |= *(f+1);
                v <<= 8; v |= *(f+2);
                v <<= 8; v |= *(f+3);        
                return v;
            };    
            ustring buf; buf.append(in); if(buf.length() % 4 != 0) buf.append(4 - (buf.length() % 4),'\0');
            for(int i=0;i<buf.length();i+=4) add(make_int(&buf[i]));            
            return fence(out , fencePeroid);
        }
        ustring decode(std::string &in_){	
            std::string in = defence(in_ , fencePeroid);
            ustring out;
            std::vector<int> T (256,0);
            for (int i = 0; i < 85; i++) T[BASE85[i]] = i;
            auto add = [&](uint32_t v){        
                out.push_back((v >> 24) & 0xFF);
                out.push_back((v >> 16) & 0xFF);
                out.push_back((v >> 8) & 0xFF);
                out.push_back(v & 0xFF);
            };
            auto make_int = [&](char *f){
                uint32_t v = (base_inv[*f]) * N85_4;        
                v += (base_inv[*(f+1)]) * N85_3;        
                v += (base_inv[*(f+2)]) * N85_2;        
                v += (base_inv[*(f+3)]) * N85;        
                v += (base_inv[*(f+4)]);    
                return v;
            };
            for(int i=0;i<in.length();i+=5) add(make_int(&in[i]));
            for(int i=0;i<4;i++) if (out.back() == (uchar)'\0') out.pop_back(); else break;    
            return out;
        }    

    private:
        const char *base;        
        std::vector<int> base_inv;        
};
class B64codec : public Codec
{
    // Snippet from https://stackoverflow.com/a/34571089
    public:
        B64codec(){
            base = BASE64;
            std::vector<int> inv(256, -1); for (int i = 0; i < 64; i++) inv[base[i]] = i;
            base_inv = inv;
        }       
        std::string encode(ustring &in){
            std::string out;
            int val = 0, valb = -6;
            for (uchar c : in)
            {
                val = (val << 8) + c;
                valb += 8;
                while (valb >= 0)
                {
                    out.push_back(base[(val >> valb) & 0x3F]);
                    valb -= 6;
                }
            }
            if (valb > -6)
                out.push_back(base[((val << 8) >> (valb + 8)) & 0x3F]);
            while (out.size() % 4)
                out.push_back('=');                
            return fence(out , fencePeroid);;
        }
        ustring decode(std::string &in_){
            std::string in = defence(in_ , fencePeroid);
            ustring out;            
            int val = 0, valb = -8;
            for (char c : in)
            {
                if (base_inv[c] == -1)
                    break;
                val = (val << 6) + base_inv[c];
                valb += 6;
                if (valb >= 0)
                {
                    out.push_back(((val >> valb) & 0xFF));
                    valb -= 8;
                }
            }
            return out;
        }

    private:
        const char *base;
        std::vector<int> base_inv;                
};
class BlockCipher{
    public:
        BlockCipher(Codec *codec_){
            codec = codec_;
            sbox = SBOX; inv_sbox = new uchar[256];
            for (int i=0;i<256;i++) inv_sbox[sbox[i]] = i;
        }        
        std::string encryptECB(ustring &str, ustring &pass)
        {
            pad(str, padchar);
            for (int i = 0; i + 16 <= str.length(); i += 16)
                encypher(&str[i], i, pass);
            return codec->encode(str);
        }
        ustring decryptECB(std::string &str, ustring &pass)
        {
            ustring dec = codec->decode(str);
            for (int i = 0; i + 16 <= dec.length(); i += 16)
                decypher(&dec[i], i, pass);
            unpad(dec);
            return dec;
        }        
        std::string encryptCBC(ustring &str, ustring &pass, uchar *iv)
        {
            pad(str, padchar);
            uchar vec[16];
            memcpy(vec, iv, 16);
            for (int i = 0; i + 16 <= str.length(); i += 16)
            {
                encypher(&str[i], i, pass);
                XOR(&str[i], &vec[0], 16);
                memcpy(vec, &str[i], 16);
            }
            return codec->encode(str);
        }
        ustring decryptCBC(std::string &str, ustring &pass, uchar *iv)
        {	
            ustring dec = codec->decode(str);
            uchar vec[16], prev[16];
            memcpy(vec, iv, 16);
            for (int i = 0; i + 16 <= dec.length(); i += 16)
            {
                memcpy(prev, &dec[i], 16);
                XOR(&dec[i], &vec[0], 16);
                decypher(&dec[i], i, pass);
                memcpy(vec, prev, 16);
            }	
            unpad(dec);
            return dec;
        }

    private:     
        Codec * codec;   
        const uchar * sbox;
        uchar * inv_sbox;        
        void XOR(uchar *a, uchar *b, int length){
            for (int i = 0; i < length; i++) *(a + i) ^= *(b + i);
        }    
        void encypher(uchar *block, int offset,ustring &pass){
            // S-S-X-S-S-X-S
            for (int i = 0; i < 15; i++)
            {		
                block[i] = sbox[block[i]];
                block[i] = sbox[block[i]];
                block[i] ^= pass[(offset + i) % pass.length()];
                block[i] = sbox[block[i]];
                block[i] = sbox[block[i]];
                block[i] ^= pass[(offset + i) % pass.length()];
                block[i] = sbox[block[i]];
            }
        }
        void decypher(uchar *block, int offset, ustring &pass){
            // S-X-S-S-X-S-S
            for (int i = 0; i < 15; i++)
            {
                block[i] = inv_sbox[block[i]];
                block[i] ^= pass[(offset + i) % pass.length()];
                block[i] = inv_sbox[block[i]];
                block[i] = inv_sbox[block[i]];
                block[i] ^= pass[(offset + i) % pass.length()];
                block[i] = inv_sbox[block[i]];
                block[i] = inv_sbox[block[i]];
            }
        }
        unsigned long crc32(ustring &str){
            unsigned long crc = 0xFFFFFFFFul;
            for(uchar c : str)
                crc = (crc >> 8) ^ crc32_table[(crc ^ c) & 0xFF];		
        	return crc;
        }
        void pad(ustring &str, uchar padding){
            // Pad to 16N+4(checksum)+1(length) bytes
            int r = str.length() % 16 == 0 ? 0 : 16 - str.length() % 16;
            unsigned long crc = crc32(str);
            str.append(r, padding);
            str.push_back((uchar)crc);
            str.push_back((uchar)(crc >> 8));
            str.push_back((uchar)(crc >> 16));
            str.push_back((uchar)(crc >> 24));
            str.push_back((uchar)(r + 64));	
        }
        void unpad(ustring &str){		
            int r = (int)str.back() - 64; str.pop_back();
            // Will pop last 4(checksum)+1(length) bytes,checksum is then valiadated	
            if (r < 0 || r > str.length())
                throw std::runtime_error("Obscure input");
            unsigned long crc = 0;
            for(int i=1;i<=4;i++) { crc |= str.back(); crc <<= i != 4 ? 8 : 0;str.pop_back();}		
            while (r--) str.pop_back();
            // Verify checksum
            unsigned long r_crc = crc32(str);	
            if (r_crc != crc)
                throw std::runtime_error("Bad integrity");
        }        
};
extern "C"
{	
    #define MIN(a,b) ( a < b ? a : b )
    // Defining exposed APIs
    #define SELECT Codec *codec;\
            if(mode[0] == 'A')\
                codec = new B85codec();\
            else codec = new B64codec();\
            BlockCipher cipher = BlockCipher(codec);
    #define PREPARE ustring password = (uchar *)pass;\
            if (password.length() == 0) password.append(padchar,16);\
            uchar iv_[16]={0}; memcpy(iv_,iv,MIN(strlen(iv),16));                   
	char *encrypt(char *src,char *pass, char *iv, char *mode){		                
        SELECT;        
        PREPARE;
        ustring str = (uchar *)src; std::string text;
		if (mode[1] == 'A')
            text = cipher.encryptCBC(str,password,iv_);	
        else
            text = cipher.encryptECB(str,password);	
		// Make a copy since string will be recycled shortly after
		return strdup((char*)text.c_str());
	}
	char *decrypt(char *src,char *pass, char *iv,char *mode){	
        SELECT;
        PREPARE;        
        std::string str = src; ustring text;
		if (mode[1] == 'A')
            text = cipher.decryptCBC(str,password,iv_);	
        else
            text = cipher.decryptECB(str,password);	
		// Make a copy since string will be recycled shortly after
		return strdup((char*)text.c_str());
	}
	int main(int argc,char* argv[]){	
        if (argc > 4){
            char * iv; if (argc == 6) iv = argv[5]; else iv = new char[16]();            
            std::string mode = argv[1]; std::string result;            
            if (mode.compare("encrypt") == 0){
                result = encrypt(argv[3],argv[4],iv,argv[2]);                
            }else if (mode.compare("decrypt") == 0){
                result = decrypt(argv[3],argv[4],iv,argv[2]);            
            }
            if(result.length()){
                std::cout << result << std::endl;
                return 0;
            }            
		}        
        std::cout << "usage : [encrypt/decrypt] [A/B][A/B] [TEXT] [PASSWORD] [IV(optional,defaults to 0s)]\n";        
		return 1;        
	}
};