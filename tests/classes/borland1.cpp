#include <stdio.h>

class Parent
{
	public:
		Parent();

		virtual int A();
		virtual void B(int x) ;
		virtual void C(int, int) {}

	private:
		int mA;
		int mB;
		int mC;
};

class Child : public Parent
{
	public:
		Child();
		
		virtual int A();
		//virtual int B(int);
		//virtual int C(int, int);
		virtual void D() {}
		virtual void E(int) {}
		virtual void F(int, int) {}

	private:
		int mD;
		int mE;
		int mF;
};

Parent::Parent()
{
	printf("Parent constructor\n");
}

int Parent::A()
{
	printf("In Parent::A()\n");
	mA = 1;
	return 2;
}

void Parent::B(int x)
{
	if (x)
		throw x;
	else
		throw this;
}

Child::Child()
{
	printf("Child constructor\n");
}

int Child::A()
{
	printf("In Child::A()\n");
	mD = 3;
	return 4;
}

int CallA(Parent* p)
{
	return p->A();
}

int main()
{
	Parent p;
	Child c;

	printf("Before try...\n");
	try
	{
		CallA(&p);
		CallA(&c);
		p.B(10);
	}
	catch (int x)
	{
		printf("Catched %i\n", x);
	}
	catch (...)
	{
		printf("Cathced anything\n");
	}
	printf("After catch...\n");
	
	return 0;
}
