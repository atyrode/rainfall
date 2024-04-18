class N
{
    public:
        N(int x) : number(x)
        {
        }

        void setAnnotation(char *input)
        {
            memcpy(annotation, input, strlen(input));
        }

        virtual int operator+(N &some)
        {
            return number + some.number;
        }

        virtual int operator-(N &some)
        {
            return number - some.number
        }

    private:
        char annotation[100];
        int number;
};

int main(int argc, char **argv)
{
	if (argc <= 1)
        exit(1);

	N *five = new N(5);
	N *six = new N(6);

	N &five = *five
    N &six = *six;

	five.setAnnotation(argv[1]);

	return five + six;
}