#include <stdio.h>
#include <string.h>
#include <cstdlib>

#include "crack.h"
#include "psd.h"
#include "pcap_handler.cpp"

int main(int argc, char* argv[])
{
	FlagParams flags;
	unsigned char ch;
	setDefaults(&flags);

	if(argc<2){usage(); return 1;}
	while((ch = crack(argc, argv, "r|v|", 0)) != NULL)
	{
		switch(ch)
		{
			case 'r': flags.runMode = atoi(arg_option); break;
			case 'v': flags.verbosity = atoi(arg_option);	break;
			default: usage(); return 0;
		}
	}

	char* filename = argv[arg_index]; //filename of pcap file should be last in arg on command line

	switch(flags.runMode)
	{
		case 0://online mode
			runOnline();
			break;
		case 1://offline mode on selected pcap file
			runOffline(filename);
			break;
		default:
			printf("invalid running mode was selected\n");

	}

	return 0;
}

int usage()
{
	printf("--------------------------------------\n");
	printf("Usage:\n");
	printf("-r[val] -v[val] filename\n\n");
	printf("e.g.>>> ./psd -v1 -r1 filename.pcap\n");
	printf("Verbose mode (0:normal, 1:detailed)\n");
	printf("Run mode (0:online, 1:offline)\n");
	printf("--------------------------------------\n");
	return 0;
}
int setDefaults(FlagParams *flags)
{
	flags->runMode = 0;
	flags->verbosity = 0;

	return 0;
}
