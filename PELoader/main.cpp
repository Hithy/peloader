#include "PELoader.h"


char loadfile[] = "test.exe";
char targetfile[] = "ntprint.exe";

int main(int argc, char *argv[])
{
	PELoader pl;
	int ret;
	char *lf = loadfile;
	char *tf = targetfile;

	if (argc == 3)
	{
		lf = argv[1];
		tf = argv[2];
	}
	else if (argc == 2)
	{
		lf = argv[1];
	}
	//else
	//{
	//	printf("Invalid param\n");
	//	exit(-1);
	//}
	ret = pl.InjectFromFile(lf);
	if (ret != PELoader::PE_SUCCESS)
	{
		printf("Fail to load target file: %d\n",ret);
		return 0;
	}
	else
	{
		printf("load target file...ok\n");
	}
	ret = pl.CreateFakeProc(tf);
	if (ret != PELoader::PE_SUCCESS)
	{
		printf("Fail to CreateFakeProc\n");
		return 0;
	}
	else
	{
		printf("CreateFakeProc...ok\n");
	}

	ret = pl.MapImage(0);
	if (ret != PELoader::PE_SUCCESS)
	{
		printf("Fail to MapImage\n");
		return 0;
	}
	else
	{
		printf("MapImage...ok\n");
	}
	pl.Run();
	return 0;
}