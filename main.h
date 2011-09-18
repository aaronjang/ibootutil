#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/usb/USB.h>
#include <IOKit/usb/USBSpec.h>
#include <IOKit/usb/IOUSBLib.h>
#include <IOKit/IOCFPlugIn.h>
#include <sys/stat.h>
#include <readline/readline.h>
#include <getopt.h>
#include "payloads.h"

#define RECOVERY 0x1281//USB serial codes
#define DFU 0x1227

#define REQUEST_COMMAND 0x40
#define REQUEST_FILE 0x21
#define REQUEST_STATUS 0xA1

#define CPID_IPHONE2G 8900
#define CPID_IPOD1G 8900
#define CPID_IPHONE3G 8900
#define CPID_IPOD2G 8720
#define CPID_IPHONE3GS 8920
#define CPID_IPOD3G 8922
#define CPID_IPAD1G 8930
#define CPID_IPHONE4 8930
#define CPID_IPOD4G 8930
#define CPID_APPLETV2 8930
#define CPID_IPHONE42 8930

static int verbosity = 0, timeout=1000;
#define ibootutil_printf(...) { \
if(verbosity != 0) \
printf(__VA_ARGS__); \
}

struct iBootUSBConnection {
	io_service_t usbService;
	IOUSBDeviceInterface **deviceHandle;
	IOUSBInterfaceInterface **interfaceHandle;
	CFStringRef name, serial;
	UInt8 responsePipeRef;
	unsigned int idProduct, open;
};
typedef struct iBootUSBConnection *iBootUSBConnection;


void iDevice_print(iBootUSBConnection connection);
iBootUSBConnection iDevice_open(uint32_t productID);
void iDevice_close(iBootUSBConnection connection);
iBootUSBConnection iDevice_open_attempts(int attempts);
iBootUSBConnection iDevice_reconnect(iBootUSBConnection connection, int initial_pause);
int iDevice_send_command(iBootUSBConnection connection, const char *command);
int iDevice_request_status(iBootUSBConnection connection, int flag);
int iDevice_send_file(iBootUSBConnection connection, const char *path);
void iDevice_reset(iBootUSBConnection connection);
int iDevice_usb_control_msg_exploit(iBootUSBConnection connection, const char *payload);


int iDevice_control_transfer(iBootUSBConnection connection , 
							 uint8_t bmRequestType,
							 uint8_t bRequest,
							 uint16_t wValue,
							 uint16_t wIndex,
							 unsigned char *data,
							 uint16_t wLength,
							 unsigned int timeout);

int iDevice_reset_counters(iBootUSBConnection connection);
int iDevice_finish_transfer(iBootUSBConnection connection);


int limera1n_exploit(iBootUSBConnection connection);//GeoHot's exploit......we miss you
int steaks4uce_exploit(iBootUSBConnection connection);//Chronic-Dev Team Exploit

int iDevice_read_response(iBootUSBConnection connection);
int iDevice_start_shell(iBootUSBConnection connection, const char *prompt);