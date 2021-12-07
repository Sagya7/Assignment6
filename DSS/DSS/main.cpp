#include <iostream>
#include <stdlib.h>
#include <stdint.h>
#include <iostream>
#include <math.h>
#include "largenum.h"
#include <time.h>
#include <sstream>
#include <iomanip>
#include "ripemd.c"

using namespace std;

std::string uint8_to_hex_string(const uint8_t *v, const size_t s) {
	std::stringstream ss;

	ss << std::hex << std::setfill('0');

	for (int i = 0; i < s; i++) {
		ss << std::hex << std::setw(2) << static_cast<int>(v[i]);
	}

	return ss.str();
}

BigNum m, p, q, g, One, r, s, y;

void SigningAlgo(BigNum x)
{
	BigNum k, hashm;
	string hashmstring, kstring, rstring, sstring;
	uint8_t msg[100];
	uint8_t hash[20];

	cout << "\nEnter the message greater than 100 bit: ";
	cin >> hashmstring;
	hashm = StringToArray(hashmstring);

	memcpy(msg, hashmstring.c_str(), sizeof(msg));
	ripemd(msg, 100, hash);
	std::string hash_message = uint8_to_hex_string(hash, 20);
	std::cout << "\nHash of message :" << hash_message << std::endl;

	k = PwrMod(StringToArray(to_string(rand())), One, Sub(q, One));
	kstring = value_number(k);

	r = PwrMod(PwrMod(g, k, p), One, q);
	s = PwrMod(Mul(Inverse(k, q), Add(StringToArray(hash_message), Mul(x, r))), One, q);

	rstring = value_number(r);
	sstring = value_number(s);


	cout << "\n\nAfter signing Digital signature, r and s are :";
	cout << "\n\tr=" << rstring;
	cout << "\n\ts=" << sstring;
}

bool verifySignature(BigNum r, BigNum s)
{
	BigNum w, h, u1, u2, v, nr, ns;
	string receivedmessage, recievedr, receiveds;

	uint8_t msg[100];
	uint8_t hash[20];

	cout << "\nEnter message : ";
	cin >> receivedmessage;
	cout << "\nEnter r : ";
	cin >> recievedr;
	cout << "\nEnter s : ";
	cin >> receiveds;

	h  = StringToArray(receivedmessage);
	nr = StringToArray(recievedr);
	ns = StringToArray(receiveds);

	memcpy(msg, receivedmessage.c_str(), sizeof(msg));
	ripemd(msg, 100, hash);
	std::string hash_verify = uint8_to_hex_string(hash, 20);
	std::cout << "\nHash output :" << hash_verify << std::endl;

	w = Inverse(ns, q);
	u1 = PwrMod(Mul(StringToArray(hash_verify), w), One, q);
	u2 = PwrMod(Mul(nr, w), One, q);
	v = PwrMod((PwrMod(Mul(PwrMod(g, u1, p), PwrMod(y, u2, p)), One, p)), One, q);

	string v_str;
	v_str = value_number(v);

	if (v_str.compare(recievedr) == 0)
		return true;
	else
		return false;
}

int main()
{
	BigNum h, x;
	string hstring, gstring, ystring, xstring;
	One.Num[0] = 1;
	srand(time(NULL));

	p = StringToArray("8490596416367848650087159567646773591615403553294465336662715867127232816933488346501617931682626979");
	q = StringToArray("4245298208183924325043579783823386795807701776647232668331357933563616408466744173250808965841313489");

	cout << "\nImplementation of DSS\n";

	DivResult mid;
	mid = DivLarge(Sub(p, One), q);

	h = PwrMod(StringToArray(to_string(rand())), One, Sub(p, StringToArray("2")));
	hstring = value_number(h);

	g = PwrMod(h, mid.Result, p);
	gstring = value_number(g);

	x = PwrMod(StringToArray(to_string(rand())), One, Sub(q, One));
	xstring = value_number(x);

	y = PwrMod(g, x, p);
	ystring = value_number(y);


	cout << "\nPublic key is  :";
	cout << "\n\tp=" << value_number(p);
	cout << "\n\tq=" << value_number(q);
	cout << "\n\tg=" << gstring;
	cout << "\n\ty=" << ystring;

	cout << "\n\nPrivate key is :";
	cout << "\n\tx=" << xstring;

	while (1) {

		printf("\nSigning the message\n");

		SigningAlgo(x);

		printf("\nVerifying the sign\n");

		bool result = verifySignature(r, s);

		if (result == true)
			cout << "\n Signatures are matching\n";
		else
			cout << "\n Signatures are not matching\n";

	}
	return 0;
}