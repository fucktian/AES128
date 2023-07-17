#include<iostream>
#include<string>
#include<vector>

using namespace std;

// ����ֻѡȡ��8bit
#define MOD 256

// s �У� ������Կ���ɺͼ���ʱ���ֽڴ���
static const int S[16][16] = { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

// ��s �У� �����ڽ���ʱ�� ���ֽڱ任
static const int S1[16][16] = { 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

// ������ֵ��
// ���ｫԭ���ĸ���ճ���������ֳ������ĳ��� long long
// ԭ�����ڵ�8λ����int�ޣ��������
static const long long Rcon[10] = {
	0x01000000, 0x02000000,
	0x04000000, 0x08000000,
	0x10000000, 0x20000000,
	0x40000000, 0x80000000,
	0x1b000000, 0x36000000
};

// ���ַ�ת����
int ch_to_int(char& ch);

// ���ڷ��㿼�ǣ�����дһ���ַ�ת�����ֵĺ���
int ch_to_int(char& ch)
{
	int ans = 0;
	// ���ֵ�ʱ��
	if (ch >= 48 && ch <= 57)
	{
		ans = ch - '0';
	}
	// 16������a �� f
	else if (ch >= 'a' && ch <= 'f')
	{
		ans = ch - 'a' + 10;
	}
	// ����ڱ�ʵ��������У���ʵ�������е���
	else if (ch >= 'A' && ch <= 'F')
	{
		ans = ch - 'A' + 10;
	}
	return ans;
}

// ��16�����ַ���תΪ����
long long str_long(string str)
{
	long long ans = 0;
	// �����ַ��������ַ��������ݱ�Ϊ16��������
	for (char ch : str)
	{
		ans = ans * 16 + ch_to_int(ch);
	}
	return ans;
}



// Ȼ����дһ������ת16�����ַ����İɣ�ֻ����Сд��
// ��Ե���ʵ�ǵ���16����
string int_to_chs(long long num)
{
	string ans = "";
	while (num)
	{
		// ͨ��λ����õ�����λ
		int x = num & 0xf;
		// ������ֵ��������
		if (x <= 9)
		{
			char ch = x + '0';
			ans += ch;
		}
		else
		{
			char ch = x - 10 + 'a';
			ans += ch;
		}
		// ��λ����ʵ�൱�� / 16
		num >>= 4;
	}
	// Ȼ��ת�ַ�
	int left = 0, right = ans.length() - 1;
	// ˫ָ��ʵ���ַ�����ת
	while (left < right)
	{
		char  ch = ans[left];
		ans[left] = ans[right];
		ans[right] = ch;
		left++;
		right--;
	}
	return ans;
}

// ���ȷ���
vector<string> group_key(string& key)
{
	// ����
	vector<string> groups(4);
	// ��ʼ�±�
	int index = 0;
	// ����
	for (string& g : groups)
	{
		g = key.substr(index, 8);
		index += 8;
	}
	return groups;
}

// �ֽ�ѭ��
string loop_wordbyte(string& wi_1);

// �ֽڴ���
string wordbyte_sub(string& wi_1);

// �ֳ������
string xor_with_const(string& wi_1, int rounds);


// ��չ��ʱ���±�Ϊ4 �ı���ʱ����Ҫ�鷳һЩ����Ҫʹ��һ���任��T����
string T(string& wi_1, int round)
{
	// T �任��3���ֹ��ɣ� ���Կ�����д��������
	// �Ƚ�����ѭ��
	string ans = loop_wordbyte(wi_1);
	// Ȼ���ֽڴ���
	ans = wordbyte_sub(ans);
	// ����������
	ans = xor_with_const(ans, round);

	return ans;
}

// �ֽ�ѭ��ʵ��
string loop_wordbyte(string& wi_1)
{
	string ans = wi_1.substr(2) + wi_1.substr(0, 2);
	return ans;
}

// �ֽڴ��� ��ʵ��
string wordbyte_sub(string& wi_1)
{
	int len = wi_1.length();
	string ans = "";
	for (int i = 0; i < len; i += 2)
	{`
		// �Ȼ�ȡ��ǰ���±�
		int x = ch_to_int(wi_1[i]), y = ch_to_int(wi_1[i + 1]);
		// Ȼ���ȡ��ǰ������
		int num = S[x][y];
		// �Ƚ���ֵת��Ϊ�ַ���
		string s = int_to_chs(num);
	
		// Ȼ����Ļ���0
		while (s.length() < 2)
		{
			s = "0" + s;
		}

		// ������
		ans += s;
	}
	return ans;
}

// �ֳ������
string xor_with_const(string& wi_1, int rounds)
{
	// �Ƚ��ַ�����Ϊ����
	long long num = 0;
	for (int i = 0; i < 8; ++i)
	{
		char ch = wi_1[i];
		num = num * 16 + ch_to_int(ch);
	}
	// ���������
	num ^= Rcon[rounds];

	// ��numת��Ϊ�ַ���
	string res = int_to_chs(num);
	while (res.length() < 8)
	{
		res = "0" + res;
	}
	return res;
}

// дһ���ַ�����Ӧ��16���������ĺ���
string string_xor(string s1, string s2)
{
	long long num1 = str_long(s1), num2 = str_long(s2);
	long long num = num1 ^ num2;
	// �ٰ�����תΪ�ַ���
	string ans = int_to_chs(num);
	// ����8λ��ʱ��λ
	while (ans.length() < 8)
	{
		ans = "0" + ans;
	}
	return ans;
}


// ��Ҫ������Կ����չ
vector<string> extend_key(string& key)
{
	// �ȷ���
	vector<string> w_key = group_key(key);
	for (int i = 0; i < 40; ++i)
	{
		string w = "";
		int index = 4 + i;
		string temp = w_key[index - 1];
		// 4 �ı�����ʱ����Ҫ����T����
		if (index % 4 == 0)
		{
			temp = T(temp, index / 4 - 1);
		}
		w = string_xor(temp, w_key[index - 4]);

		// ѹ��������
		w_key.push_back(w);
	}

	return w_key;
}

// ����λ����
vector<string> move_row(vector<string>& s)
{
	vector<string> ans = s;
	// �����Ƚ��鷳�ĵط�
	// �ַ���������ʵÿ���Ƕ�Ӧһ��, ������ʵ�Ƕ�Ӧ���н�����λ
	// һ�ж�Ӧ������16��������������Ҫ����һ���ƶ�����ʵ���Ƕ�Ӧ����һ��
	for (int i = 0; i < 4; ++i)
	{
		int k = i * 2;
		// ��ԭ�������Ӧ������λ�������ַ��������������λ
		for (int j = 0; j < 4; ++j)
		{
			ans[j][k] = s[(j + i) % 4][k];
			ans[j][k + 1] = s[(j + i) % 4][k + 1];
		}
	}
	return ans;
}

// д�������ָ�һ���ַ���������Ϊ8��4��
vector<string> split_s(string& s)
{
	vector<string> ans;
	for (int i = 0; i < s.length(); i += 2)
	{
		ans.emplace_back(s.substr(i, 2));
	}
	return ans;
}

string int_ch2(int num)
{
	string ans = int_to_chs(num);
	// ������Ϊ��ȷ��ֻ����λ�ַ���
	while (ans.length() < 2)
	{
		ans = "0" + ans;
	}
	return ans;
}

// ��λ��������ʵ������GF��2^8���ķ�Χ�����ݴβ���
int power(int num)
{
	int ans = (num << 1) % MOD;
	// �������λ��1
	if (num & 0x80)
	{
		ans ^= 0x1b;
	}
	return ans;
}

// �����������л���
vector<string> col_confuse(vector<string>& s)
{
	vector<string> ans = s;
	// �㷨�ж�Ӧ�����У���߾�ֱ�ӱ�����У����ַ�
	for (int i = 0; i < 4; ++i)
	{
		// ��Ҫ�Ƚ��ַ�����ֳ�����һ�飬��4��
		auto temp = split_s(s[i]);
		// ��ת������
		int s0 = str_long(temp[0]), s1 = str_long(temp[1]), s2 = str_long(temp[2]),
			s3 = str_long(temp[3]);
		// ����������ֵ
		int t0 = power(s0) ^ power(s1) ^ s1 ^ s2 ^ s3;
		int t1 = s0 ^ power(s1) ^ power(s2) ^ s2 ^ s3;
		int t2 = s0 ^ s1 ^ power(s2) ^ s3 ^ power(s3);
		int t3 = s0 ^ power(s0) ^ s1 ^ s2 ^ power(s3);
		// ת�����ַ��������
		ans[i] = int_ch2(t0) + int_ch2(t1) + int_ch2(t2) + int_ch2(t3);
	}
	return ans;
}

// дһ�����Ժ���
void show(vector<string>& text)
{
	for (auto t : text)
	{
		cout << t;
	}
	cout << endl;
}

// �ȶ���һ�� aes ���ܺ���
void aes(string& plain_text, string& key)
{
	// ����չ��Կ
	vector<string> keys = extend_key(key);

	int index = 0;
	// Ȼ�����10�ֵ���
	// ��Ҫ֪��������ʵ��32λ��������Ҫ��4��
	// �����Ȱ�����Ҳ����

	// һ��ʼ���Ƚ���һ������Կ��
	vector<string> texts = group_key(plain_text);
	for (int i = 0; i < 4; ++i)
	{
		texts[i] = string_xor(texts[i], keys[i]);
	}
	index += 4;
	// Ȼ��ʮ�ε���
	for (int k = 0; k < 10; ++k)
	{
		for (int j = 0; j < 4; ++j)
		{
			// �����ֽڴ���
			texts[j] = wordbyte_sub(texts[j]);
		}
		// Ȼ��������λ
		texts = move_row(texts);

		if (k < 9)
		{
			// �����л���
			texts = col_confuse(texts);
		}

		// ����Կ��
		for (int i = 0; i < 4; ++i)
		{
			texts[i] = string_xor(texts[i], keys[i + index]);
		}

		index += 4;
	}
	string ans = "";
	for (int i = 0; i < 4; ++i)
	{
		ans += texts[i];
	}
	cout << ans << endl;
}

// ����λ�����������
vector<string> in_move_row(vector<string>& s)
{
	vector<string> ans = s;
	// ���ڱ���������
	for (int i = 0; i < 4; ++i)
	{
		int k = i * 2;
		// ��ԭ�������Ӧ������λ�������ַ��������������λ
		for (int j = 0; j < 4; ++j)
		{
			ans[j][k] = s[(j - i + 4) % 4][k];
			ans[j][k + 1] = s[(j - i + 4) % 4][k + 1];
		}
	}
	return ans;
}

// ���ֽڴ���
string in_wordbyte_sub(string& wi_1)
{
	int len = wi_1.length();
	string ans = "";
	for (int i = 0; i < len; i += 2)
	{
		// �Ȼ�ȡ��ǰ���±�
		int x = ch_to_int(wi_1[i]), y = ch_to_int(wi_1[i + 1]);
		// Ȼ���ȡ��ǰ������
		int num = S1[x][y];
		// �Ƚ���ֵת��Ϊ�ַ���
		string s = int_to_chs(num);
		// Ȼ����Ļ���0
		while (s.length() < 2)
		{
			s = "0" + s;
		}

		// ������
		ans += s;
	}
	return ans;
}


// �л�������任
vector<string> in_col_confuse(vector<string>& s)
{
	// ��任��ʵԭ���ı任���������󣬶�Ӧ0xe, 0xb, 0xd, 0x9
	// 4 ��

	vector<string> ans = s;
	for (int i = 0; i < 4; ++i)
	{
		// �ȷָ��4����λ����
		auto temp = split_s(s[i]);
		// ת��������
		vector<int> nums(4);
		for (int j = 0; j < 4; ++j)
		{
			nums[j] = str_long(temp[j]);
		}
		vector<int> t4(4, 0);
		for (int j = 0; j < 4; ++j)
		{
			for (int t = 0; t < 4; ++t)
			{
				int k = (t - j + 4) % 4;
				t4[j] ^= power(power(power(nums[t])));		// ��ʾ8
				switch (k)
				{
				case 0:		// 0xe = 8 + 4 + 2
				{
					t4[j] ^= power(power(nums[t])) ^ power(nums[t]);
					break;
				}
				case 1:		// 0xb = 8 + 2 + 1
				{
					t4[j] ^= power(nums[t]) ^ nums[t];
					break;
				}
				case 2:		// 0xd = 8 + 4 + 1
				{
					t4[j] ^= power(power(nums[t])) ^ nums[t];
					break;
				}
				default:	// 0x9 = 8 + 1
					t4[j] ^= nums[t];
					break;
				}

			}
		}
		// ������ת�����ַ����洢
		ans[i] = int_ch2(t4[0]) + int_ch2(t4[1]) + int_ch2(t4[2]) + int_ch2(t4[3]);
	}

	return ans;
}

// ����дһ�� aes ���ܺ���
void in_aes(string& text, string& key)
{
	// ����չ��Կ
	auto keys = extend_key(key);

	// ��ʼ�±�
	int index = 40;

	// �����ķ���
	vector<string> texts = group_key(text);

	// һ��ʼ�Ƚ�����������Կ��
	for (int i = 0; i < 4; ++i)
	{
		texts[i] = string_xor(texts[i], keys[index + i]);
	}
	index -= 4;

	// Ȼ��ʮ�ε���
	for (int i = 0; i < 10; ++i)
	{
		// ��������λ
		texts = in_move_row(texts);

		// Ȼ�����ֽڴ��������
		for (int j = 0; j < 4; ++j)
		{
			texts[j] = in_wordbyte_sub(texts[j]);
		}

		// ����Կ��
		for (int j = 0; j < 4; ++j)
		{
			texts[j] = string_xor(texts[j], keys[index + j]);
		}

		// �������һ�֣���Ҫ�л�����任
		if (i < 9)
		{
			texts = in_col_confuse(texts);
		}
		index -= 4;
	}

	show(texts);
}

int main(int argc, char** argv)
{
	int op;
	cin >> op;			// �����ʶ��
	string text, key;
	cin >> text >> key;		// �������Ļ������ģ� �Լ���ʼ��Կ
	// ���ݱ�ʶ�����������ܻ��ǽ���
	if (op == 0)
	{
		aes(text, key);
	}
	else
	{
		in_aes(text, key);
	}

	return 0;
}
