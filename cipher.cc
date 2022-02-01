/**
 * mos9527's Toy Cipher
 * 
 * Implements CBC & ECB stream cipherer, with error checking and more ;)
*/
#include <vector>
#include <iostream>
#include <cstring>
typedef unsigned char uchar;
typedef std::vector<unsigned char> uvector;
/**
 * @brief Pre-generated data
 */
/* Generated with utils/permutate.py */
const char BASE85[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+-;<=>?@^_`{|}~";
const char BASE64[] = "MOS4UEFGHJ/klpq9527LNPQRrtuvdefhwxyz0is1368KComIngTV+WABDXYZabcjfoRax*hUuvjiojasTYYou";
const uchar SBOX[] = {65, 36, 54, 31, 208, 109, 108, 56, 127, 53, 248, 86, 181, 21, 67, 0, 114, 178, 209, 176, 196, 112, 68, 106, 224, 214, 33, 105, 38, 189, 1, 90, 150, 192, 13, 129, 70, 246, 174, 182, 236, 9, 72, 135, 201, 213, 148, 226, 187, 147, 144, 97, 111, 169, 245, 134, 141, 46, 190, 188, 253, 107, 99, 158, 6, 180, 234, 113, 76, 92, 30, 167, 45, 103, 7, 37, 5, 35, 60, 225, 151, 119, 14, 220, 250, 120, 24, 238, 82, 49, 66, 179, 200, 211, 94, 183, 58, 249, 132, 50, 143, 122, 175, 69, 163, 233, 128, 23, 79, 212, 191, 15, 146, 91, 83, 27, 227, 130, 115, 102, 228, 34, 252, 202, 40, 243, 195, 164, 223, 89, 121, 16, 96, 140, 237, 207, 142, 22, 123, 118, 48, 240, 20, 81, 168, 12, 165, 51, 124, 172, 8, 32, 241, 206, 149, 29, 161, 85, 64, 162, 173, 232, 19, 185, 152, 100, 160, 153, 52, 197, 184, 17, 75, 170, 216, 57, 11, 63, 139, 159, 199, 71, 255, 198, 155, 42, 104, 55, 251, 25, 77, 131, 247, 215, 244, 84, 43, 74, 4, 62, 219, 194, 235, 186, 78, 10, 87, 166, 117, 110, 116, 231, 204, 133, 98, 230, 44, 18, 193, 59, 93, 2, 138, 3, 156, 61, 80, 125, 217, 145, 222, 73, 177, 28, 239, 88, 101, 254, 95, 47, 136, 137, 210, 39, 26, 218, 157, 171, 126, 205, 154, 242, 221, 229, 203, 41};
/* CRC-32D polynomial */
const unsigned long CRC32D = 0xA833982B;
/**
 * @brief Base class for Codecs
 */
class Codec{
    public:
        /**
         * @brief Encodes uchar string to printable string
         * 
         * @param in 
         * @return std::string 
         */
        virtual std::string encode(uvector &in){
            return std::string((char*)&in[0]);
        }
        /**
         * @brief Decodes encoded string into uchar string
         * 
         * @param in 
         * @return uvector 
         */
        virtual uvector decode(std::string &in){
            return uvector(in.begin(),in.end());
        }
        /**
         * @brief Apply rail fence cipher to get permutated output
         * 
         * @param in 
         * @param fence_period 
         * @return std::string 
         */
        std::string fence(std::string &in,int fence_period){
            if (fence_period == 0) return in;
            std::string s;                                                            
            int groups = in.length() / fence_period;
            int plen   = fence_period * groups;
            for(int i=0;i < plen;i++){
                int r = fence_period * (i % groups) + i / groups;
                s.push_back(in[r]);                                
            } // only data length of 4N are fencable. Don't do anything beyond this range
            s.append(&in[plen],in.length() - plen);            
            return s;
        }    
        /**
         * @brief Un-permutate rail fenced cipher to get orignal input
         * 
         * @param in 
         * @param fence_period 
         * @return std::string 
         */
        std::string defence(std::string &in,int fence_period){
            if (fence_period == 0) return in;
            std::string s;
            int groups = in.length() / fence_period;
            int plen   = fence_period * groups;
            for(int i=0;i < plen;i++){
                int r = (i / fence_period) + (i - (i / fence_period) * fence_period) * groups;                
                s.push_back(in[r]);
            }            
            s.append(&in[plen],in.length() - plen);
            return s;
        }      

    private:        
        int fence_period;
        char const *base;        
        std::vector<int> *base_inv;
};
/**
 * @brief Non-standard Base-85 implmentation with optional rail fence permutation
 */
class B85codec : public Codec
{
    #define N85_4 52200625
    #define N85_3 614125
    #define N85_2 7225
    #define N85   85
    public:
        /**
         * @brief Construct a new B85codec object
         * 
         * @param base_ the base (of 85 different characters) to use
         * @param fence_period_ period for fencing. set 0 to disable it
         */
        B85codec(const char* base_,int fence_period_){
            fence_period = fence_period_;
            base = base_;
            std::vector<int> inv(256, 0); for (int i = 0; i < 86; i++) inv[base[i]] = i;
            base_inv = inv;
        }
        /**
         * @brief Encodes uchar string to base-85 printable string,with given settings.
         * 
         * With overall 80% (1.25x size) effeicency
         * 
         * @param in 
         * @return std::string 
         */
        std::string encode(uvector &in){	            
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
            uvector buf; buf.insert(buf.begin(),in.begin(),in.end()); int p=0;
            while (p++,(buf.size() + 1) % 4 != 0) buf.push_back(0); // pad data with 0s
            buf.push_back(p - 1); // where the last padding is the length padded  
            
            for(int i=0;i<buf.size();i+=4) add(make_int(&buf[i]));
            return fence(out,fence_period);
        }        
        /**
         * @brief Decodes string encoded by us with given settings
         * 
         * @param in_ 
         * @return uvector 
         */
        uvector decode(std::string &in_){	
            std::string in = defence(in_,fence_period);
            uvector out;
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
            if(in.length() % 5 != 0 || in.length() < 5)
                throw std::runtime_error("Bad Base85 string.");
            for(int i=0;i<in.length();i+=5) add(make_int(&in[i]));            
            uchar p = out.back() + 1; // copy the pad length
            if (p >= out.size())
                throw std::runtime_error("Incompatible Base85 string.");
            while(p--) out.pop_back(); // then unpad with the length (1 byte) itself            
            return out;
        }    

    private:
        int fence_period;
        const char *base;        
        std::vector<int> base_inv;        
};
/**
 * @brief Base-64 implmentation with optional rail fence permutation
 */
class B64codec : public Codec
{
    // Snippet from https://stackoverflow.com/a/34571089
    public:
        /**
         * @brief Construct a new B64codec object
         * 
         * @param base_ the base (of 64 different characters) to use
         * @param fenced_ whether to use fence cipher or not
         */
        B64codec(const char* base_,int fence_period_){
            fence_period = fence_period_;
            base = base_;
            std::vector<int> inv(256, -1); for (int i = 0; i < 64; i++) inv[base[i]] = i;
            base_inv = inv;
        }       
        /**
         * @brief Encodes uchar string to base-64 printable string,with given settings.
         * 
         * With overall 75% (1.33x+ size) effeicency
         * 
         * @param in 
         * @return std::string 
         */        
        std::string encode(uvector &in){
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
            return fence(out,fence_period);
        }
        /**
         * @brief Decodes string encoded by us with given settings
         * 
         * @param in_ 
         * @return ustring 
         */
        uvector decode(std::string &in_){
            std::string in = defence(in,fence_period);
            uvector out;            
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
        int fence_period;
        const char *base;
        std::vector<int> base_inv;                
};
/**
 * @brief Implements common block cipher algorithms & our custom cipherer,padding,etc
 */
class BlockCipher{
    public:
        /**
         * @brief Construct a new Block Cipher object,which
         * throws std::runtime_error() when cipher operation fails.
         * 
         * @param codec_ the pointer of a derived Codec instance
         */
        ~BlockCipher(){
            delete inv_sbox;
            delete CRC32;            
        }

        BlockCipher(Codec *codec_,const unsigned long crc32_poly,const uchar padchar_){
            codec = codec_;
            padchar = padchar_;            
            sbox = SBOX; 
            inv_sbox = new uchar[256];
            CRC32 = new unsigned long[256]; 
            unsigned int r=0;            
            // Use rotated polynominal bits for crc32 calculation
            unsigned long invpoly = 0,t=crc32_poly;
            for (int i=0;i<32;i++){
                invpoly |= t & 1;
                invpoly <<= i == 31 ? 0 : 1;
                t >>= 1;
            }            
            auto crc = [&](int n){
                unsigned int r = n;
                for(int i=0;i<8;i++)
                    r = r & 1 ? (r >> 1) ^ invpoly : r >> 1;
                return r;
            };            
            for (int i=0;i<256;i++){
                inv_sbox[sbox[i]] = i;
                CRC32[i] = crc(i);
            }                        
        }  
        /**
         * @brief Encrypts uchar string with ECB (Electronic Codebook)
         * And encodes it with given settings.
         * @param str 
         * @param pass 
         * @return std::string 
         */
        std::string encryptECB(uvector &str, uvector &pass)
        {
            pad(str, padchar);
            for (int i = 0; i + 16 <= str.size(); i += 16)
                encypher(&str[i], i, pass);
            return codec->encode(str);
        }
        /**
         * @brief Decrypts uchar string with ECB (Electronic Codebook)
         * And decodes it with given settings
         * @param str 
         * @param pass 
         * @return ustring 
         */
        uvector decryptECB(std::string &str, uvector &pass)
        {
            uvector dec = codec->decode(str);
            for (int i = 0; i + 16 <= dec.size(); i += 16)
                decypher(&dec[i], i, pass);
            unpad(dec);
            return dec;
        }       
        /**
         * @brief Encrypts uchar string with CBC (Cipher Block chaining)
         * And encodes it with given settings
         *           
         * @param str 
         * @param pass 
         * @param iv 
         * @return std::string 
         */
        std::string encryptCBC(uvector &str, uvector &pass, uchar *iv)
        {            
            pad(str, padchar);
            uchar vec[16];
            std::memcpy(vec, iv, 16);
            for (int i = 0; i + 16 <= str.size(); i += 16)
            {
                encypher(&str[i], i, pass);
                XOR(&str[i], &vec[0], 16);
                std::memcpy(vec, &str[i], 16);
            }
            std::string r = codec->encode(str);            
            return r;
        }
        /**
         * @brief  Decrypts uchar string with CBC (Cipher Block chaining)
         * And decodes it with given settings
         * @param str 
         * @param pass 
         * @param iv 
         * @return ustring 
         */
        uvector decryptCBC(std::string &str, uvector &pass, uchar *iv)
        {	
            uvector dec = codec->decode(str);
            uchar vec[16], prev[16];
            std::memcpy(vec, iv, 16);
            for (int i = 0; i + 16 <= dec.size(); i += 16)
            {
                std::memcpy(prev, &dec[i], 16);
                XOR(&dec[i], &vec[0], 16);
                decypher(&dec[i], i, pass);
                std::memcpy(vec, prev, 16);
            }	
            unpad(dec);
            return dec;
        }

    private:     
        Codec * codec;   
        uchar padchar;
        const uchar * sbox;
        uchar * inv_sbox;  
        unsigned long * CRC32;      
        void XOR(uchar *a, uchar *b, int length){
            for (int i = 0; i < length; i++) *(a + i) ^= *(b + i);
        }    
        void encypher(uchar *block, int offset,uvector &pass){
            // S-S-X-S-S-X-S
            for (int i = 0; i < 15; i++)
            {		
                block[i] = sbox[block[i]];
                block[i] = sbox[block[i]];
                block[i] ^= pass[(offset + i) % pass.size()];
                block[i] = sbox[block[i]];
                block[i] = sbox[block[i]];
                block[i] ^= pass[(offset + i) % pass.size()];
                block[i] = sbox[block[i]];
            }
        }
        void decypher(uchar *block, int offset, uvector &pass){
            // S-X-S-S-X-S-S
            for (int i = 0; i < 15; i++)
            {
                block[i] = inv_sbox[block[i]];
                block[i] ^= pass[(offset + i) % pass.size()];
                block[i] = inv_sbox[block[i]];
                block[i] = inv_sbox[block[i]];
                block[i] ^= pass[(offset + i) % pass.size()];
                block[i] = inv_sbox[block[i]];
                block[i] = inv_sbox[block[i]];
            }
        }
        unsigned long crc32(uvector &str){
            unsigned long crc = 0xFFFFFFFFul;
            for(uchar c : str)
                crc = (crc >> 8) ^ CRC32[(crc ^ c) & 0xFF];		
        	return crc;
        }
        void pad(uvector &str, uchar padding){
            // Pad to 16N with 4(checksum)+1(length) bytes
            unsigned long crc = crc32(str);
            int r = 0;            
            while(r++,(str.size() + 5) % 4 != 0) str.push_back(padding);                        
            str.push_back(crc & 0xFF);
            str.push_back((crc >> 8) & 0xFF);
            str.push_back((crc >> 16) & 0xFF);
            str.push_back((crc >> 24) & 0xFF);
            str.push_back(r);
        }
        void unpad(uvector &str){		            
            int r = (int)str.back() - 1; str.pop_back();            
            // Will pop last 4(checksum)+1(length) bytes,checksum is then valiadated	
            if (r > str.size())
                throw std::runtime_error("Obscure input.");
            unsigned long crc = 0;
            for(int i=1;i<=4;i++) { crc |= str.back(); crc <<= i != 4 ? 8 : 0;str.pop_back();}		
            while (r--) str.pop_back();
            // Verify checksum
            unsigned long r_crc = crc32(str);	
            if (r_crc != crc)
                throw std::runtime_error("Bad integrity.");            
        }        
};
extern "C"
{	
    /**
     * @brief APIs exposed to WASM and command line
     */
    #define MODE_BASE64 0b100 // otherwise, Base85    
    #define MODE_CBC    0b010 // otherwise, ECB    
    #define MODE_FENCE  0b001 // otherwise, No fencing
    #define MIN(a,b) ( a < b ? a : b )    
    #define READY Codec *codec;\
            if(mode & MODE_BASE64)\
                 codec = new B64codec(BASE64, mode & MODE_FENCE ? 4 : 0);\
            else codec = new B85codec(BASE85, mode & MODE_FENCE ? 4 : 0);\
            BlockCipher cipher = BlockCipher(codec,CRC32D,'/');\
            uchar iv_[16]={0}; std::memcpy(iv_,iv,MIN(strlen(iv),16));\
            uvector password = uvector(pass,pass + strlen(pass));

	char *encrypt(char *src,char *pass, char *iv, int mode){		                
        READY;                
        uvector str = uvector(src,src+strlen(src) + 1); std::string text;
        if (password.size() == 0) password.insert(password.begin(),1,'\0');
		if (mode & MODE_CBC)
            text = cipher.encryptCBC(str,password,iv_);	
        else
            text = cipher.encryptECB(str,password);			       
        return strdup(text.c_str());
	}
	char *decrypt(char *src,char *pass, char *iv,int mode){	
        READY;       
        std::string str = src; uvector text;
        if (str.length() == 0)
            throw std::runtime_error("Empty input.");
        if (password.size() == 0) password.insert(password.begin(),1,'\0');
		if (mode & MODE_CBC)
            text = cipher.decryptCBC(str,password,iv_);	
        else
            text = cipher.decryptECB(str,password);	        
		return strdup((char*)&text[0]);
	}
	int main(int argc,char* argv[]){	
        if (argc > 4){
            char * iv; if (argc == 6) iv = argv[5]; else iv = new char[16]();            
            std::string op = argv[1]; char *result;     
            int mode = std::atoi(argv[2]);
            if (op.compare("encrypt") == 0){
                result = encrypt(argv[3],argv[4],iv,mode);                
            }else if (op.compare("decrypt") == 0){
                result = decrypt(argv[3],argv[4],iv,mode);            
            }            
            std::cout << result << std::endl;
            return 0;  
		}        
        std::cout << "usage : [encrypt/decrypt] [MODE] [TEXT] [PASSWORD] [IV]" << std::endl;
        std::cout << "        MODE : integer. masks availbale:" << std::endl;
        std::cout << "               -Base 85 or 64  0b1--" << std::endl;
        std::cout << "               -CBC or ECB     0b-1-" << std::endl;
        std::cout << "    (period=4) -Fenced or not  0b--1" << std::endl;
        std::cout << "        TEXT : string. Ciphertext or Plaintext." << std::endl;
        std::cout << "    PASSWORD : string. Can leave empty and then 16 *padchar* will be used." << std::endl;
        std::cout << "          IV : truncates at 16 chars at pads with 0s otherwise,can leave empty." << std::endl;        
		return 1;        
	}
};