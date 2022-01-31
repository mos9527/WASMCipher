/**
 * mos9527's Toy Cipher
 * 
 * Implements CBC & ECB stream cipherer, with error checking and more ;)
*/
#include <vector>
#include <iostream>
#include <string.h>
#include <stdexcept>
// for memcpy(),strlen()
typedef unsigned char uchar;
typedef std::basic_string<unsigned char> ustring;
#define min(a,b) (a<b?a:b)
const char base64[] = "MOS4UEFGHJ/klpq9527LNPQRrtuvdefhwxyz0is1368KComIngTV+WABDXYZabcjfoRax*hUuvjiojasTYYou";
// from python permutate.py "<insert base64 string here>" 9527 
// with **only** 300k tries
const uchar sbox[] = {65, 36, 54, 31, 208, 109, 108, 56, 127, 53, 248, 86, 181, 21, 67, 0, 114, 178, 209, 176, 196, 112, 68, 106, 224, 214, 33, 105, 38, 189, 1, 90, 150, 192, 13, 129, 70, 246, 174, 182, 236, 9, 72, 135, 201, 213, 148, 226, 187, 147, 144, 97, 111, 169, 245, 134, 141, 46, 190, 188, 253, 107, 99, 158, 6, 180, 234, 113, 76, 92, 30, 167, 45, 103, 7, 37, 5, 35, 60, 225, 151, 119, 14, 220, 250, 120, 24, 238, 82, 49, 66, 179, 200, 211, 94, 183, 58, 249, 132, 50, 143, 122, 175, 69, 163, 233, 128, 23, 79, 212, 191, 15, 146, 91, 83, 27, 227, 130, 115, 102, 228, 34, 252, 202, 40, 243, 195, 164, 223, 89, 121, 16, 96, 140, 237, 207, 142, 22, 123, 118, 48, 240, 20, 81, 168, 12, 165, 51, 124, 172, 8, 32, 241, 206, 149, 29, 161, 85, 64, 162, 173, 232, 19, 185, 152, 100, 160, 153, 52, 197, 184, 17, 75, 170, 216, 57, 11, 63, 139, 159, 199, 71, 255, 198, 155, 42, 104, 55, 251, 25, 77, 131, 247, 215, 244, 84, 43, 74, 4, 62, 219, 194, 235, 186, 78, 10, 87, 166, 117, 110, 116, 231, 204, 133, 98, 230, 44, 18, 193, 59, 93, 2, 138, 3, 156, 61, 80, 125, 217, 145, 222, 73, 177, 28, 239, 88, 101, 254, 95, 47, 136, 137, 210, 39, 26, 218, 157, 171, 126, 205, 154, 242, 221, 229, 203, 41};
// from python utils/permutate.py
const uchar inv_sbox[] = {15, 30, 221, 223, 198, 76, 64, 74, 150, 41, 205, 176, 145, 34, 82, 111, 131, 171, 217, 162, 142, 13, 137, 107, 86, 189, 244, 115, 233, 155, 70, 3, 151, 26, 121, 77, 1, 75, 28, 243, 124, 255, 185, 196, 216, 72, 57, 239, 140, 89, 99, 147, 168, 9, 2, 187, 7, 175, 96, 219, 78, 225, 199, 177, 158, 0, 90, 14, 22, 103, 36, 181, 42, 231, 197, 172, 68, 190, 204, 108, 226, 143, 88, 114, 195, 157, 11, 206, 235, 129, 31, 113, 69, 220, 94, 238, 132, 51, 214, 62, 165, 236, 119, 73, 186, 27, 23, 61, 6, 5, 209, 52, 21, 67, 16, 118, 210, 208, 139, 81, 85, 130, 101, 138, 148, 227, 248, 8, 106, 35, 117, 191, 98, 213, 55, 43, 240, 241, 222, 178, 133, 56, 136, 100, 50, 229, 112, 49, 46, 154, 32, 80, 164, 167, 250, 184, 224, 246, 63, 179, 166, 156, 159, 104, 127, 146, 207, 71, 144, 53, 173, 247, 149, 160, 38, 102, 19, 232, 17, 91, 65, 12, 39, 95, 170, 163, 203, 48, 59, 29, 58, 110, 33, 218, 201, 126, 20, 169, 183, 180, 92, 44, 123, 254, 212, 249, 153, 135, 4, 18, 242, 93, 109, 45, 25, 193, 174, 228, 245, 200, 83, 252, 230, 128, 24, 79, 47, 116, 120, 253, 215, 211, 161, 105, 66, 202, 40, 134, 87, 234, 141, 152, 251, 125, 194, 54, 37, 192, 10, 97, 84, 188, 122, 60, 237, 182};
// from python utils/invbox.py
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
// from `python utils/crc_table_gen.py 0xA833982B`
const uchar padchar = '/';
void XOR(uchar *a, uchar *b, int length){
	for (int i = 0; i < length; i++) *(a + i) ^= *(b + i);
}
// Snippet from https://stackoverflow.com/a/34571089
std::string base64_encode(ustring &in){
	std::string out;
	int val = 0, valb = -6;
	for (uchar c : in)
	{
		val = (val << 8) + c;
		valb += 8;
		while (valb >= 0)
		{
			out.push_back(base64[(val >> valb) & 0x3F]);
			valb -= 6;
		}
	}
	if (valb > -6)
		out.push_back(base64[((val << 8) >> (valb + 8)) & 0x3F]);
	while (out.size() % 4)
		out.push_back('=');
	return out;
}
ustring base64_decode(std::string &in){
	ustring out;
	std::vector<int> T(256, -1);
	for (int i = 0; i < 64; i++)
		T[base64[i]] = i;

	int val = 0, valb = -8;
	for (char c : in)
	{
		if (T[c] == -1)
			break;
		val = (val << 6) + T[c];
		valb += 6;
		if (valb >= 0)
		{
			out.push_back(((val >> valb) & 0xFF));
			valb -= 8;
		}
	}
	return out;
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
	int r = 16 - str.length() % 16;
	unsigned long crc = crc32(str);
	str.append(r, padding);
	str.append(1, (uchar)crc         & 0xFF);
	str.append(1, (uchar)(crc >> 8)  & 0xFF);
	str.append(1, (uchar)(crc >> 16) & 0xFF);
	str.append(1, (uchar)(crc >> 24) & 0xFF);
	str.append(1, (uchar)r + 64);	
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
std::string encrypt_ecb(ustring &str, ustring &pass)
{
	pad(str, padchar);
	for (int i = 0; i + 16 <= str.length(); i += 16)
		encypher(&str[i], i, pass);
	return base64_encode(str);
}
ustring decrypt_ecb(std::string &str, ustring &pass)
{
	ustring dec = base64_decode(str);
	for (int i = 0; i + 16 <= dec.length(); i += 16)
		decypher(&dec[i], i, pass);
	unpad(dec);
	return dec;
}
std::string encrypt_cbc(ustring &str, ustring &pass, uchar *iv)
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
	return base64_encode(str);
}
ustring decrypt_cbc(std::string &str, ustring &pass, uchar *iv)
{	
	ustring dec = base64_decode(str);	
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
extern "C"
{	
// Defining exposed APIs
#define TRUNC(a,b) memcpy(a,b,min(strlen(b),16));
	char *encrypt(char *src,char *pass, char *iv){		
		ustring str = (uchar *)src;		
		ustring password = (uchar *)pass;
		if (password.length() == 0) password.append(padchar,16);
		uchar iv_[16]={0}; TRUNC(iv_,iv);		
		std::string cipher = encrypt_cbc(str,password,iv_);	
		// Make a copy since string will be recycled shortly after
		return strdup((char*)cipher.c_str());
	}
	char *decrypt(char *src,char *pass, char *iv){	
		std::string str = src;
		ustring password = (uchar *)pass;		
		if (password.length() == 0) password.append(padchar,16);
		uchar iv_[16]={0}; TRUNC(iv_,iv);		
		ustring cipher = decrypt_cbc(str,password,iv_);
		return strdup((char*)cipher.c_str()); // same goes here
	}
	int main(int argc,char* argv[]){
		if (argc == 5){			
			std::string mode = argv[1];
			std::string result;			
			if (mode.compare("encrypt") == 0) result.append(encrypt(argv[2],argv[3],argv[4]));
			else                              result.append(decrypt(argv[2],argv[3],argv[4]));
			std::cout << result << '\n';
		} else {
			std::cout << "usage : encrypt/decrypt TEXT PASSWORD IV\n";
		}
		return 0;
	}
}