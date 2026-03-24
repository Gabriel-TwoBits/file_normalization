#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

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

int totalLinesCounter(FILE* file);
int validLinesCounter(FILE* file);
void trimWhiteSpaces(char* text);

void validLinesToStruct(char* fileContent, SecurityEvent events[]);

void padronizeID(SecurityEvent events[], int size);
void padronizeSeverity(SecurityEvent events[], int size);
void padronizeStatus(SecurityEvent events[], int size);
void padronizeSource(SecurityEvent events[], int size);

void writeCleanFile(FILE* file, SecurityEvent events[], int numberOfLines);

void stringToUpper(char* str);

int main(){
	FILE* rawFile = openFile("raw_security_events.txt", "r");
	FILE* cleanedFile = openFile("security_events_cleaned.txt", "w");

	printf("Opening raw file...\n");

	if(rawFile == NULL){
		printf("Could not open raw file!");
		return 1;
	}else{
		printf("File was open with success!\n");
	};

	printf("Creating clean file...\n");

	if(cleanedFile == NULL){
		printf("Could not create new file!");
		return 1;
	}else{
		printf("File created with success!\n");
	};

	int rawTotalLines = totalLinesCounter(rawFile);

	FileInfo fileInfo;
	fileInfo.fileSize = checkFileSize(rawFile);
	fileInfo.numberOfValidLines = validLinesCounter(rawFile);
	rewind(rawFile);

	printf("\nThe origin file has:\n%d bytes of size and %d total lines.\n", fileInfo.fileSize, rawTotalLines);

	char* fileContent = (char*) malloc(fileInfo.fileSize + 1);

	fread(fileContent, 1, fileInfo.fileSize, rawFile);
	fclose(rawFile);

	fileContent[fileInfo.fileSize] = '\0';
	trimWhiteSpaces(fileContent);

	SecurityEvent* events = malloc(sizeof(SecurityEvent) * fileInfo.numberOfValidLines);
	if(events == NULL){
		printf("Could not allocate space to struct!");
		return 1;
	};
	memset(events, 0, sizeof(events));

	validLinesToStruct(fileContent, events);
	free(fileContent);

	padronizeID(events, fileInfo.numberOfValidLines);
	padronizeSeverity(events, fileInfo.numberOfValidLines);
	padronizeStatus(events, fileInfo.numberOfValidLines);
	padronizeSource(events, fileInfo.numberOfValidLines);

	printf("\nWriting on clean file...\n");

	writeCleanFile(cleanedFile, events, fileInfo.numberOfValidLines);
	fclose(cleanedFile);

	cleanedFile = fopen("security_events_cleaned.txt", "r");
    if(cleanedFile == NULL) return 1;

	int cleanTotalLines = (totalLinesCounter(cleanedFile) - 1); // Minus one cause of the header
	printf("\nClean file has %d total valid lines, bringing the invalid lines to a total of %d.\n", cleanTotalLines, (rawTotalLines - cleanTotalLines));

	free(events);

	printf("\nClean file written with success!\nExiting...\n");

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

int totalLinesCounter(FILE* file){
	int linesCounted = 0;
	int character;

	while((character = fgetc(file)) != EOF){
		if(character == '\n') linesCounted++;
	};

	return linesCounted;
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
			if(separatorsCounter >= 3){
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
	int i = 0;
	char separators[] = ",;|";

	line = strtok(fileContent, "\n");

	while(line != NULL){
		int count = 0;
		for(int j = 0; line[j] != '\0'; j++) if(strchr(separators, line[j])) count ++;

		if(count >= 3){
			char *loginStr = NULL;

			if (strstr(line, "id=")) {
                sscanf(line, " %*[^=]=%[^,;|\n]%*[,;|\n]" 
                             " %*[^=]=%[^,;|\n]%*[,;|\n]" 
                             " %*[^=]=%[^,;|\n]%*[,;|\n]" 
                             " %*[^=]=%[^,;|\n]%*[,;|\n]" 
                             " %*[^=]=%m[^,;|\n]%*[,;|\n]"
                             " %*[^=]=%[^,;|\n]",          
                       events[i].event_id, events[i].device, events[i].severity,
                       events[i].status, &loginStr, events[i].source);
            } else {
                sscanf(line, " %[^,;|\n]%*[,;|\n] %[^,;|\n]%*[,;|\n] %[^,;|\n]%*[,;|\n] %[^,;|\n]%*[,;|\n] %m[^,;|\n]%*[,;|\n] %[^,;|\n]",
                       events[i].event_id, events[i].device, events[i].severity,
                       events[i].status, &loginStr, events[i].source);
            };
			
			if(loginStr != NULL) {
                if(!isdigit((unsigned char)loginStr[0])){
                    events[i].failed_logins = 0;
                } else {
                    events[i].failed_logins = atoi(loginStr);
                };
                
                events[i].is_valid = 1;
                free(loginStr);
                i++;
            };
		};
		line = strtok(NULL, "\n");
	};
};

void padronizeID(SecurityEvent events[], int size){
	for(int i = 0; i < size; i++){
		stringToUpper(events[i].event_id);
	};
};

void padronizeSource(SecurityEvent events[], int size){
	for(int i = 0; i < size; i++){
		stringToUpper(events[i].source);
	};
};

void padronizeSeverity(SecurityEvent events[], int size){
	char *acceptedValues[] = {"LOW", "MED", "MEDIUM", "HIGH", "CRIT", "CRITICAL"};
	int valids = sizeof(acceptedValues) / sizeof(acceptedValues[0]);

	for(int i = 0; i < size; i++){

		stringToUpper(events[i].severity);

		int found = 0;

		for(int k = 0; k < valids; k++){
			if(strcmp(events[i].severity, acceptedValues[k]) == 0){
				found = 1;
				
				if(strcmp(events[i].severity, "MED") == 0) strcpy(events[i].severity, "MEDIUM");
				if(strcmp(events[i].severity, "CRIT") == 0) strcpy(events[i].severity, "CRITICAL");
				
				break;
			};
		};

		if(found == 0){
			events[i].is_valid = 0;
		};
	};
};

void padronizeStatus(SecurityEvent events[], int size){
	char *acceptedValues[] = {"OPEN", "CLOSED", "DONE", "RESOLVED", "INVESTIGATING", "ANALYSIS", "IN_PROGRESS"};
	int valids = sizeof(acceptedValues) / sizeof(acceptedValues[0]);

	for(int i = 0; i < size; i++){

		stringToUpper(events[i].status);

		int found = 0;

		for(int k = 0; k < valids; k++){
			if(strcmp(events[i].status, acceptedValues[k]) == 0){
				found = 1;

				if(strcmp(events[i].status, "DONE") == 0 || strcmp(events[i].status, "RESOLVED") == 0) strcpy(events[i].status, "CLOSED");
				if(strcmp(events[i].status, "ANALYSIS") == 0 || strcmp(events[i].status, "IN_PROGRESS") == 0) strcpy(events[i].status, "INVESTIGATING");

				break;
			};
		};

		if(found == 0){
			events[i].is_valid = 0;
		};
	};
};

void writeCleanFile(FILE* file, SecurityEvent events[], int numberOfLines){
	if(file != NULL){
		fprintf(file, "EVENT_ID;DEVICE;SEVERITY;STATUS;FAILED_LOGINS;SOURCE\n");

		for (int i = 0; i < numberOfLines; i++){
			if(events[i].is_valid == 0) continue;
			fprintf(file, "%s;%s;%s;%s;%d;%s\n", 
				events[i].event_id, 
				events[i].device, 
				events[i].severity,
				events[i].status, 
				events[i].failed_logins, 
				events[i].source);
		};
	};
};

void stringToUpper(char* str){
	if(str == NULL) return;

    while (*str){
        *str = toupper((unsigned char)*str);
        str++;
    };
};