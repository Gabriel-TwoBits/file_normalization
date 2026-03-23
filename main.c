#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
	char event_id[32];
	char device[64];
	char severity[16];
	char status[20];
	int failed_logins;
	char source[32];
	int is_valid;
} SecurityEvent;

FILE* openFile(char* fileName, char* mode);
long checkFileSize(FILE* file);
void trimWhiteSpaces(char* text);

int main(){
	FILE* rawFile = openFile("raw_security_events.txt", "r");
	FILE* cleanedFile = openFile("security_events_cleaned.txt", "w");

	if(rawFile == NULL){
		printf("Could not open raw file!");
		return 1;
	};

	if(cleanedFile == NULL){
		printf("Could not create new file!");
		return 1;
	};

	long fileSize = checkFileSize(rawFile);

	char* fileContent = (char*) malloc(fileSize + 1);

	fread(fileContent, 1, fileSize, rawFile);
	fclose(rawFile);

	fileContent[fileSize] = '\0';

	printf("%s\n", fileContent);

	fclose(cleanedFile);

	return 0;
};

FILE* openFile(char* fileName, char* mode){
	FILE* file = fopen(fileName, mode);

	if(file == NULL){
		printf("Error when opening file!");
		return NULL;
	};

	return file;
};

long checkFileSize(FILE* file){
	fseek(file, 0, SEEK_END);
	long fileSize = ftell(file);
	rewind(file);

	return fileSize;
};

void trimWhiteSpaces(char* text){

};
