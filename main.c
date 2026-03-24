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

typedef struct {
	int fileSize;
	int numberOfValidLines;
} FileInfo;

FILE* openFile(char* fileName, char* mode);
long checkFileSize(FILE* file);
int validLinesCounter(FILE* file);
void trimWhiteSpaces(char* text);
void validLinesToStruct(char* fileContent, SecurityEvent events[]);

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

	FileInfo fileInfo;
	fileInfo.fileSize = checkFileSize(rawFile);
	fileInfo.numberOfValidLines = validLinesCounter(rawFile);
	rewind(rawFile);

	char* fileContent = (char*) malloc(fileInfo.fileSize + 1);

	fread(fileContent, 1, fileInfo.fileSize, rawFile);
	fclose(rawFile);

	fileContent[fileInfo.fileSize] = '\0';
	trimWhiteSpaces(fileContent);

	SecurityEvent events[fileInfo.numberOfValidLines];
	memset(events, 0, sizeof(events));

	validLinesToStruct(fileContent, events);

	printf("%s\n", fileContent);

	for (int i = 0; i < fileInfo.numberOfValidLines; i++){
		fprintf(cleanedFile, "%s\t;%s\t;%s\t;%s\t;%d\t;%s\n", 
        events[i].event_id, 
        events[i].device, 
        events[i].severity,
        events[i].status, 
        events[i].failed_logins, 
        events[i].source);
	}

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

int validLinesCounter(FILE* file){
	char separators[] = ",;|\n";
	int character;
	int separatorsCounter = 0, validLines = 0;

	while ((character = fgetc(file)) != EOF){
		if(strchr(separators, character)){
			separatorsCounter++;
		};

		if(character == '\n'){
			if(separatorsCounter == 6){
				validLines++;
			};

			separatorsCounter = 0;
		}
	};

	rewind(file);

	return validLines;
};

void trimWhiteSpaces(char* text){
	char *i = text;
	char *j = text;

	while(*i){
		if(*i != ' '){
			*j++ = *i;
		};
		i++;
	};

	*j = '\0';
};

void validLinesToStruct(char* fileContent, SecurityEvent events[]){
	char *line;
	int event_index = 0, i = 0;
	char separators[] = ",;|";

	line = strtok(fileContent, "\n");

	while(line != NULL){
		int count = 0;

		for(int j = 0; line[j] != '\0'; j++){
			if(strchr(separators, line[j])) count ++;
		};

		if(count == 5){
			sscanf(line, "%[^,;|\n]%*[,;|\n]"  // event_id
                          "%[^,;|\n]%*[,;|\n]"  // device
                          "%[^,;|\n]%*[,;|\n]"  // severity
                          "%[^,;|\n]%*[,;|\n]"  // status
                          "%d%*[,;|\n]"         // failed_logins (inteiro)
                          "%[^,;|\n]",          // source
                   events[i].event_id,
                   events[i].device,
                   events[i].severity,
                   events[i].status,
                   &events[i].failed_logins,
                   events[i].source);

			events[i].is_valid = 1;
			i++;
		};
		line = strtok(NULL, "\n");
	};
};