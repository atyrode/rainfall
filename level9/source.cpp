class N {
public:
	int num;
	int (N::*func)(N &);
	char annotation[100]; // <- v6 est initialisé par Hexray avec new(0x6C) => 108 bytes, mais à ebp-8

	N(int value) : num(value) {
		this->func = &N::operator+;
	}
	int operator+(N &some) {
		return this->num + some.num;
	}
	int operator-(N &some) {
		return this->num - some.num;
	}
	void setAnnotation(char *input) {
		memcpy(this->annotation, input, strlen(input));
	}
};

int		main(int argc, char **argv)
{
	if (argc < 1)
		_exit(1);

	N *n1 = new N(5);
	N *n2 = new N(6);

	n1->setAnnotation(argv[1]);
	return (n2->*(n2->func))(*n1);
}