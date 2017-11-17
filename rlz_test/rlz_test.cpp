#include <iostream>
#include <fstream>
#include <vector>

#include"rlz_id.h"
#include"\code\rlz_id\crypto_hmac\hmac_sha2.h"

bool InitKey(std::string file_path);
std::string GetChromeStartup_urls(std::string url, std::string mac_id);
std::string GetChromeUrlRestore_on_startup(std::string index, std::string mac_id);
std::string GetChromeSuper_mac(std::string path, std::string mac_id);
std::string GetMessage(const std::string& device_id, const std::string& path, const std::string& value_as_string);
std::string GetDigestString(const  unsigned char * key, const int key_size, const std::string& message);
std::string GenerateHMAC(unsigned char *digest, unsigned int digest_size, bool isUpper = true);

unsigned char key_[0x41] = { 0 };

int main()
{
	std::string machine_id;
	std::string resources_path;
	std::string preferences_path;
	std::string url;

	std::cout << "输入 [resources.pak] 文件的完整路径：" <<std::endl;
	std::cin >> resources_path;
	std::cout << "输入欲设置的url：" << std::endl;
	std::cin >> url;
	url = "[\"" + url + "\"]";
	if (GetMachineId(&machine_id))
		std::cout << "machine_id: " << machine_id << std::endl;

	InitKey(resources_path);

	auto startup_urls = GetChromeStartup_urls(url, machine_id);
	auto restore_on_startup = GetChromeUrlRestore_on_startup("4", machine_id);

	std::cout << "计算完成，替换以下内容： 注：需确保浏览器已关闭。" << std::endl;
	std::cout << " >>> url：" << url << std::endl;
	std::cout << " >>> startup_urls: " << startup_urls << std::endl;
	std::cout << " >>> restore_on_startup: " << restore_on_startup << std::endl;
	std::cout << "替换完成后按回车键继续。" << std::endl;
	
	std::cout << "输入 [Secure Preferences] 文件的完整路径：" << std::endl;
	std::cin >> preferences_path;
	

	auto super_mac = GetChromeSuper_mac(preferences_path, machine_id);
	std::cout << "计算完成，替换以下内容： 注：需确保浏览器已关闭。" << std::endl;
	std::cout << " >>> super_mac：" << super_mac << std::endl;
	std::cout << "工作已完成,按任意键关闭。" << std::endl;
	system("pause");
	return EXIT_SUCCESS;
}

bool InitKey(std::string file_path) {
	std::ifstream inF;

	////获取key
	inF.open(file_path, std::ifstream::binary);
	inF.seekg(0x28f62a);
	inF.read((char*)key_, 0x40);
	inF.close();
	key_[0x40] = 0x00;
	return true;
}

std::string GetChromeStartup_urls( std::string url,std::string mac_id) {
	auto message = GetMessage(mac_id, "session.startup_urls", url);

	auto hmac = GetDigestString(key_, 0x40, message);
	return hmac;
}

std::string GetChromeUrlRestore_on_startup(std::string index, std::string mac_id) {
	auto message = GetMessage(mac_id, "session.restore_on_startup", index);

	auto hmac = GetDigestString(key_, 0x40, message);
	return hmac;
}

std::string GetChromeSuper_mac(std::string path, std::string mac_id) {
	std::string data;
	std::string value_as_string;

	std::ifstream in(path);
	if (!in.is_open()){
		return "";
	}
	in.seekg(0, std::ios::end);
	int len = in.tellg();
	in.seekg(std::ios::beg);

	char* str = new char[len];
	in.read(str, len);
	data = str;
	in.close();
	delete str;

	auto q1 = data.find("{\"browser\":");
	auto q2 = data.find(",\"super_mac\"") - q1;
	value_as_string = data.substr(q1, q2);

	auto message = GetMessage(mac_id, "", value_as_string);

	auto hmac = GetDigestString(key_, 0x40, message);
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