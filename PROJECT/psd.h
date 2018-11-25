#ifndef PSD
#define PSD
/*
typedef struct FlagParams
{
	char verbosity;
	char runMode;
} FlagParams;

*/
typedef struct FlagParams FlagParams;

struct FlagParams{
	char verbosity;
	char runMode;
};

int usage();
int setDefaults(FlagParams *flags);


#endif
