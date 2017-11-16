#include <iostream>
#include <fstream>
#include <vector>

#include"rlz_id.h"
#include"\code\rlz_id\crypto_hmac\hmac_sha2.h"

std::string SetChromeUrl(std::string file_path, std::string url, std::string mac_id);
std::string GetMessage(const std::string& device_id, const std::string& path, const std::string& value_as_string);
std::string GetDigestString(const  unsigned char * key, const int key_size, const std::string& message);
std::string GenerateHMAC(unsigned char *digest, unsigned int digest_size, bool isUpper = true);

int main()
{
	std::string machine_id;
	std::string resources_path;
	std::string url;

	std::cout << "输入 [resources.pak] 文件的完整路径：" <<std::endl;
	std::cin >> resources_path;
	std::cout << "输入欲设置的url：" << std::endl;
	std::cin >> url;
	url = "[\"" + url + "\"]";
	if (GetMachineId(&machine_id))
		std::cout << "machine_id: " << machine_id << std::endl;

	auto hmac = SetChromeUrl(resources_path, url, machine_id);
	
	std::cout << "计算完成，请将url与密钥替换至Secure Preferences文件的startup_urls节中即可完成。注：需确保浏览器已关闭。" << std::endl;
	std::cout << " >>> url：" << url << std::endl;
	std::cout << " >>> hmac: " << hmac << std::endl;
	system("pause");
	return EXIT_SUCCESS;
}

std::string SetChromeUrl(std::string file_path, std::string url,std::string mac_id) {

	unsigned char data[0x41] = { 0 };
	//std::string value_as_string;
	std::ifstream inF;
	//value_as_string = "[\"" + url + "\"]";
	
	////获取key
	inF.open(file_path, std::ifstream::binary);
	inF.seekg(0x28f62a);
	inF.read((char*)data, 0x40);
	inF.close();
	data[0x40] = 0x00;

	auto message = GetMessage(mac_id, "session.startup_urls", url);

	auto hmac = GetDigestString(data, 0x40, message);
	return hmac;
}

std::string GetMessage(const std::string& device_id, const std::string& path, const std::string& value_as_string) {
	std::string message;
	message.reserve(device_id.size() + path.size() + value_as_string.size());
	message.append(device_id);
	message.append(path);
	message.append(value_as_string);
	return message;
}

std::string GetDigestString(const  unsigned char * key,const int key_size ,const std::string& message) {
	unsigned char mac[SHA512_DIGEST_SIZE];

	hmac_sha256((const unsigned char *)key, key_size, (unsigned char *)message.c_str(),
		message.length(), mac, SHA256_DIGEST_SIZE);

	return GenerateHMAC(mac, SHA256_DIGEST_SIZE);
}

std::string GenerateHMAC(unsigned char *digest, unsigned int digest_size, bool isUpper/*true */)
{
	char output[256] = { 0 };
	int i;

	output[2 * digest_size] = '\0';

	for (i = 0; i < (int)digest_size; i++) {
		if (isUpper)
			sprintf_s(output + 2 * i, 2 * digest_size + 2, "%02X", digest[i]);
		else
			sprintf_s(output + 2 * i, 2 * digest_size + 2, "%02x", digest[i]);
	}
	std::string ret = output;
	return ret;
}