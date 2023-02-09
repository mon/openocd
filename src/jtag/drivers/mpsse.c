// SPDX-License-Identifier: GPL-2.0-or-later

/**************************************************************************
 *   Copyright (C) 2012 by Andreas Fritiofson                              *
 *   andreas.fritiofson@gmail.com                                          *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mpsse.h"
#include "helper/log.h"
#include "helper/replacements.h"
#include "helper/time_support.h"
#include "libusb_helper.h"
#include <libusb.h>

/* Compatibility define for older libusb-1.0 */
#ifndef LIBUSB_CALL
#define LIBUSB_CALL
#endif

#define DEBUG_PRINT_BUF(buf, len) \
	do { \
		if (LOG_LEVEL_IS(LOG_LVL_DEBUG_IO)) { \
			char buf_string[32 * 3 + 1]; \
			int buf_string_pos = 0; \
			for (int i = 0; i < len; i++) { \
				buf_string_pos += sprintf(buf_string + buf_string_pos, " %02x", buf[i]); \
				if (i % 32 == 32 - 1) { \
					LOG_DEBUG_IO("%s", buf_string); \
					buf_string_pos = 0; \
				} \
			} \
			if (buf_string_pos > 0) \
				LOG_DEBUG_IO("%s", buf_string);\
		} \
	} while (0)

#define FTDI_DEVICE_OUT_REQTYPE (LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE)
#define FTDI_DEVICE_IN_REQTYPE (0x80 | LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE)

#define BITMODE_MPSSE 0x02

#define SIO_RESET_REQUEST             0x00
#define SIO_SET_LATENCY_TIMER_REQUEST 0x09
#define SIO_GET_LATENCY_TIMER_REQUEST 0x0A
#define SIO_SET_BITMODE_REQUEST       0x0B

#define SIO_RESET_SIO 0
#define SIO_RESET_PURGE_RX 1
#define SIO_RESET_PURGE_TX 2

/* Optionally try and load in FTDI D2XX, which doesn't violate GPL, as anyone
   can provide their own .dll implementing the API, it's a part of the system
   itself (NOT shipped with OpenOCD), and isn't required for OpenOCD to function
   */
#ifdef _WIN32

#include <windows.h>
#include "ftd2xx.h"

#define D2XX_SUPPORT

#endif // _WIN32

struct mpsse_ctx {
	struct libusb_context *usb_ctx;
	struct libusb_device_handle *usb_dev;
#ifdef D2XX_SUPPORT
	FT_HANDLE d2xx_dev;
#endif
	unsigned int usb_write_timeout;
	unsigned int usb_read_timeout;
	uint8_t in_ep;
	uint8_t out_ep;
	uint16_t max_packet_size;
	uint16_t index;
	uint8_t interface;
	enum ftdi_chip_type type;
	uint8_t *write_buffer;
	unsigned write_size;
	unsigned write_count;
	uint8_t *read_buffer;
	unsigned read_size;
	unsigned read_count;
	uint8_t *read_chunk;
	unsigned read_chunk_size;
	struct bit_copy_queue read_queue;
	int retval;
};

/* Returns true if the string descriptor indexed by str_index in device matches string */
static bool string_descriptor_equal(struct libusb_device_handle *device, uint8_t str_index,
	const char *string)
{
	int retval;
	char desc_string[256]; /* Max size of string descriptor */
	retval = libusb_get_string_descriptor_ascii(device, str_index, (unsigned char *)desc_string,
			sizeof(desc_string));
	if (retval < 0) {
		LOG_ERROR("libusb_get_string_descriptor_ascii() failed with %s", libusb_error_name(retval));
		return false;
	}
	return strncmp(string, desc_string, sizeof(desc_string)) == 0;
}

static bool device_location_equal(struct libusb_device *device, const char *location)
{
	bool result = false;
#ifdef HAVE_LIBUSB_GET_PORT_NUMBERS
	char *loc = strdup(location);
	uint8_t port_path[7];
	int path_step, path_len;
	uint8_t dev_bus = libusb_get_bus_number(device);
	char *ptr;

	path_len = libusb_get_port_numbers(device, port_path, 7);
	if (path_len == LIBUSB_ERROR_OVERFLOW) {
		LOG_ERROR("cannot determine path to usb device! (more than 7 ports in path)");
		goto done;
	}

	LOG_DEBUG("device path has %i steps", path_len);

	ptr = strtok(loc, "-:");
	if (!ptr) {
		LOG_DEBUG("no ':' in path");
		goto done;
	}
	if (atoi(ptr) != dev_bus) {
		LOG_DEBUG("bus mismatch");
		goto done;
	}

	path_step = 0;
	while (path_step < 7) {
		ptr = strtok(NULL, ".,");
		if (!ptr) {
			LOG_DEBUG("no more tokens in path at step %i", path_step);
			break;
		}

		if (path_step < path_len
			&& atoi(ptr) != port_path[path_step]) {
			LOG_DEBUG("path mismatch at step %i", path_step);
			break;
		}

		path_step++;
	};

	/* walked the full path, all elements match */
	if (path_step == path_len)
		result = true;

 done:
	free(loc);
#endif
	return result;
}

/* Helper to open a libusb device that matches vid, pid, product string and/or serial string.
 * Set any field to 0 as a wildcard. If the device is found true is returned, with ctx containing
 * the already opened handle. ctx->interface must be set to the desired interface (channel) number
 * prior to calling this function. */
static bool open_matching_device_libusb(struct mpsse_ctx *ctx, const uint16_t vids[], const uint16_t pids[],
	const char *product, const char *serial, const char *location)
{
	struct libusb_device **list;
	struct libusb_device_descriptor desc;
	struct libusb_config_descriptor *config0;
	int err;
	bool found = false;
	ssize_t cnt = libusb_get_device_list(ctx->usb_ctx, &list);
	if (cnt < 0)
		LOG_ERROR("libusb_get_device_list() failed with %s", libusb_error_name(cnt));

	for (ssize_t i = 0; i < cnt; i++) {
		struct libusb_device *device = list[i];

		err = libusb_get_device_descriptor(device, &desc);
		if (err != LIBUSB_SUCCESS) {
			LOG_ERROR("libusb_get_device_descriptor() failed with %s", libusb_error_name(err));
			continue;
		}

		if (!jtag_libusb_match_ids(&desc, vids, pids))
			continue;

		err = libusb_open(device, &ctx->usb_dev);
		if (err != LIBUSB_SUCCESS) {
			LOG_ERROR("libusb_open() failed with %s",
				  libusb_error_name(err));
			continue;
		}

		if (location && !device_location_equal(device, location)) {
			libusb_close(ctx->usb_dev);
			continue;
		}

		if (product && !string_descriptor_equal(ctx->usb_dev, desc.iProduct, product)) {
			libusb_close(ctx->usb_dev);
			continue;
		}

		if (serial && !string_descriptor_equal(ctx->usb_dev, desc.iSerialNumber, serial)) {
			libusb_close(ctx->usb_dev);
			continue;
		}

		found = true;
		break;
	}

	libusb_free_device_list(list, 1);

	if (!found) {
		/* The caller reports detailed error desc */
		return false;
	}

	err = libusb_get_config_descriptor(libusb_get_device(ctx->usb_dev), 0, &config0);
	if (err != LIBUSB_SUCCESS) {
		LOG_ERROR("libusb_get_config_descriptor() failed with %s", libusb_error_name(err));
		libusb_close(ctx->usb_dev);
		return false;
	}

	/* Make sure the first configuration is selected */
	int cfg;
	err = libusb_get_configuration(ctx->usb_dev, &cfg);
	if (err != LIBUSB_SUCCESS) {
		LOG_ERROR("libusb_get_configuration() failed with %s", libusb_error_name(err));
		goto error;
	}

	if (desc.bNumConfigurations > 0 && cfg != config0->bConfigurationValue) {
		err = libusb_set_configuration(ctx->usb_dev, config0->bConfigurationValue);
		if (err != LIBUSB_SUCCESS) {
			LOG_ERROR("libusb_set_configuration() failed with %s", libusb_error_name(err));
			goto error;
		}
	}

	/* Try to detach ftdi_sio kernel module */
	err = libusb_detach_kernel_driver(ctx->usb_dev, ctx->interface);
	if (err != LIBUSB_SUCCESS && err != LIBUSB_ERROR_NOT_FOUND
			&& err != LIBUSB_ERROR_NOT_SUPPORTED) {
		LOG_WARNING("libusb_detach_kernel_driver() failed with %s, trying to continue anyway",
			libusb_error_name(err));
	}

	err = libusb_claim_interface(ctx->usb_dev, ctx->interface);
	if (err != LIBUSB_SUCCESS) {
		LOG_ERROR("libusb_claim_interface() failed with %s", libusb_error_name(err));
		goto error;
	}

	/* Reset FTDI device */
	err = libusb_control_transfer(ctx->usb_dev, FTDI_DEVICE_OUT_REQTYPE,
			SIO_RESET_REQUEST, SIO_RESET_SIO,
			ctx->index, NULL, 0, ctx->usb_write_timeout);
	if (err < 0) {
		LOG_ERROR("failed to reset FTDI device: %s", libusb_error_name(err));
		goto error;
	}

	switch (desc.bcdDevice) {
	case 0x500:
		ctx->type = TYPE_FT2232C;
		break;
	case 0x700:
		ctx->type = TYPE_FT2232H;
		break;
	case 0x800:
		ctx->type = TYPE_FT4232H;
		break;
	case 0x900:
		ctx->type = TYPE_FT232H;
		break;
	default:
		LOG_ERROR("unsupported FTDI chip type: 0x%04x", desc.bcdDevice);
		goto error;
	}

	/* Determine maximum packet size and endpoint addresses */
	if (!(desc.bNumConfigurations > 0 && ctx->interface < config0->bNumInterfaces
			&& config0->interface[ctx->interface].num_altsetting > 0))
		goto desc_error;

	const struct libusb_interface_descriptor *descriptor;
	descriptor = &config0->interface[ctx->interface].altsetting[0];
	if (descriptor->bNumEndpoints != 2)
		goto desc_error;

	ctx->in_ep = 0;
	ctx->out_ep = 0;
	for (int i = 0; i < descriptor->bNumEndpoints; i++) {
		if (descriptor->endpoint[i].bEndpointAddress & 0x80) {
			ctx->in_ep = descriptor->endpoint[i].bEndpointAddress;
			ctx->max_packet_size =
					descriptor->endpoint[i].wMaxPacketSize;
		} else {
			ctx->out_ep = descriptor->endpoint[i].bEndpointAddress;
		}
	}

	if (ctx->in_ep == 0 || ctx->out_ep == 0)
		goto desc_error;

	libusb_free_config_descriptor(config0);
	return true;

desc_error:
	LOG_ERROR("unrecognized USB device descriptor");
error:
	libusb_free_config_descriptor(config0);
	libusb_close(ctx->usb_dev);
	return false;
}

#ifdef D2XX_SUPPORT

static struct {
    bool load_ok;

    FT_CreateDeviceInfoList_t FT_CreateDeviceInfoList;
    FT_Open_t                 FT_Open;
    FT_Close_t                FT_Close;
    FT_GetDeviceInfo_t        FT_GetDeviceInfo;
    FT_Read_t                 FT_Read;
    FT_Write_t                FT_Write;
    FT_SetBaudRate_t          FT_SetBaudRate;
    FT_SetBitMode_t           FT_SetBitMode;
    FT_GetBitMode_t           FT_GetBitMode;
    FT_SetLatencyTimer_t      FT_SetLatencyTimer;
	FT_Purge_t				  FT_Purge;
} d2xx;

#define LOAD_FN(name) if(!(d2xx.name = (void*)GetProcAddress(dll, #name))) return false;

bool load_d2xx(void) {
    // already loaded?
    if(d2xx.load_ok) {
        return true;
    }

    HMODULE dll = LoadLibraryA("ftd2xx.dll");

    if(!dll) {
        return false;
    }

    LOAD_FN(FT_CreateDeviceInfoList);
    LOAD_FN(FT_Open);
    LOAD_FN(FT_Close);
    LOAD_FN(FT_GetDeviceInfo);
    LOAD_FN(FT_Read);
    LOAD_FN(FT_Write);
    LOAD_FN(FT_SetBaudRate);
    LOAD_FN(FT_SetBitMode);
    LOAD_FN(FT_GetBitMode);
    LOAD_FN(FT_SetLatencyTimer);
    LOAD_FN(FT_Purge);

    d2xx.load_ok = true;
    return true;
}

const char *d2xx_error_name(FT_STATUS status)
{
	switch(status) {
        case FT_OK: return "FT_OK";
        case FT_INVALID_HANDLE: return "FT_INVALID_HANDLE";
        case FT_DEVICE_NOT_FOUND: return "FT_DEVICE_NOT_FOUND";
        case FT_DEVICE_NOT_OPENED: return "FT_DEVICE_NOT_OPENED";
        case FT_IO_ERROR: return "FT_IO_ERROR";
        case FT_INSUFFICIENT_RESOURCES: return "FT_INSUFFICIENT_RESOURCES";
        case FT_INVALID_PARAMETER: return "FT_INVALID_PARAMETER";
        case FT_INVALID_BAUD_RATE: return "FT_INVALID_BAUD_RATE";
        case FT_DEVICE_NOT_OPENED_FOR_ERASE: return "FT_DEVICE_NOT_OPENED_FOR_ERASE";
        case FT_DEVICE_NOT_OPENED_FOR_WRITE: return "FT_DEVICE_NOT_OPENED_FOR_WRITE";
        case FT_FAILED_TO_WRITE_DEVICE: return "FT_FAILED_TO_WRITE_DEVICE";
        case FT_EEPROM_READ_FAILED: return "FT_EEPROM_READ_FAILED";
        case FT_EEPROM_WRITE_FAILED: return "FT_EEPROM_WRITE_FAILED";
        case FT_EEPROM_ERASE_FAILED: return "FT_EEPROM_ERASE_FAILED";
        case FT_EEPROM_NOT_PRESENT: return "FT_EEPROM_NOT_PRESENT";
        case FT_EEPROM_NOT_PROGRAMMED: return "FT_EEPROM_NOT_PROGRAMMED";
        case FT_INVALID_ARGS: return "FT_INVALID_ARGS";
        case FT_NOT_SUPPORTED: return "FT_NOT_SUPPORTED";
        case FT_OTHER_ERROR: return "FT_OTHER_ERROR";
        case FT_DEVICE_LIST_NOT_READY: return "FT_DEVICE_LIST_NOT_READY";
        default: return "Unknown error";
    }
}

static bool jtag_d2xx_match_ids(DWORD deviceID, const uint16_t vids[], const uint16_t pids[])
{
	uint16_t pid = deviceID & 0xFFFF;
	uint16_t vid = (deviceID >> 16) & 0xFFFF;

	for (unsigned i = 0; vids[i]; i++) {
		if (vid == vids[i] &&
			pid == pids[i]) {
			return true;
		}
	}
	return false;
}

static bool open_matching_device_d2xx(struct mpsse_ctx *ctx, const uint16_t vids[], const uint16_t pids[],
	const char *product, const char *serial, const char *location)
{
    DWORD i;
    FT_HANDLE ftHandle;
    FT_STATUS status = FT_DEVICE_NOT_FOUND;
	FT_DEVICE dev;
    DWORD deviceID;
    DWORD dev_count;
	char dev_serial[16];
	char dev_desc[64];


    if(!load_d2xx()) {
        LOG_INFO("Failed to load FTDI d2xx library, using libusb");
        return false;
    }

	if(location) {
		LOG_INFO("d2xx: Cannot filter by location, using libusb");
		return false;
	}

	if(!FT_SUCCESS(d2xx.FT_CreateDeviceInfoList(&dev_count))) {
		LOG_ERROR("d2xx: FT_CreateDeviceInfoList failed");
		return false;
	}

	for(i = 0; i < dev_count; i++) {
		if(!FT_SUCCESS(status = d2xx.FT_Open(i, &ftHandle))) {
			continue;
		}

		if(!FT_SUCCESS(status = d2xx.FT_GetDeviceInfo(
				ftHandle,
				&dev,
				&deviceID,
				dev_serial,
				dev_desc,
				NULL
				))) {
			LOG_ERROR("d2xx: FT_GetDeviceInfo failed");
			d2xx.FT_Close(ftHandle);
			continue;
		}

		if (!jtag_d2xx_match_ids(deviceID, vids, pids) ||
				(product && strcmp(product, dev_desc)) ||
				(serial && strcmp(serial, dev_serial))) {
			d2xx.FT_Close(ftHandle);
			status = FT_DEVICE_NOT_FOUND;
			continue;
		}

		break;
	}

    if(!FT_SUCCESS(status)) {
        LOG_INFO("No FTDI D2XX devices found, trying libusb\n");
        return false;
    }

    ctx->d2xx_dev = ftHandle;

    LOG_INFO("Opened FTDI D2XX device\n");

    return true;
}

#else

static bool open_matching_device_d2xx(struct mpsse_ctx *ctx, const uint16_t *vid, const uint16_t *pid,
	const char *product, const char *serial, const char *location)
{
	return false;
}

#endif

/* Helper to open a device that matches vid, pid, product string and/or serial string.
 * Set any field to 0 as a wildcard. If the device is found true is returned, with ctx containing
 * the already opened handle. ctx->interface must be set to the desired interface (channel) number
 * prior to calling this function. */
static bool open_matching_device(struct mpsse_ctx *ctx, const uint16_t vids[], const uint16_t pids[],
	const char *product, const char *serial, const char *location)
{
	if (open_matching_device_d2xx(ctx, vids, pids, product, serial, location)) {
		return true;
	}

	return open_matching_device_libusb(ctx, vids, pids, product, serial, location);
}

static bool mpsse_set_latency(struct mpsse_ctx *ctx, uint8_t latency)
{
	int err;

#ifdef D2XX_SUPPORT
	FT_STATUS status;

	if (ctx->d2xx_dev) {
		status = d2xx.FT_SetLatencyTimer(ctx->d2xx_dev, latency);
		if (!FT_SUCCESS(status)) {
			LOG_ERROR("unable to set latency timer: %s", d2xx_error_name(status));
			return false;
		}
		return true;
	}
#endif

	err = libusb_control_transfer(ctx->usb_dev, FTDI_DEVICE_OUT_REQTYPE,
			SIO_SET_LATENCY_TIMER_REQUEST, latency, ctx->index, NULL, 0,
			ctx->usb_write_timeout);
	if (err < 0) {
		LOG_ERROR("unable to set latency timer: %s", libusb_error_name(err));
		return false;
	}

	return true;
}

static bool mpsse_set_bitmode(struct mpsse_ctx *ctx, uint8_t pinmask)
{
	int err;

#ifdef D2XX_SUPPORT
	FT_STATUS status;

	if (ctx->d2xx_dev) {
		status = d2xx.FT_SetBitMode(ctx->d2xx_dev, pinmask, FT_BITMODE_MPSSE);
		if (!FT_SUCCESS(status)) {
			LOG_ERROR("unable to set MPSSE bitmode: %s", d2xx_error_name(status));
			return false;
		}
		return true;
	}
#endif

	err = libusb_control_transfer(ctx->usb_dev,
			FTDI_DEVICE_OUT_REQTYPE,
			SIO_SET_BITMODE_REQUEST,
			(BITMODE_MPSSE << 8) | pinmask,
			ctx->index,
			NULL,
			0,
			ctx->usb_write_timeout);
	if (err < 0) {
		LOG_ERROR("unable to set MPSSE bitmode: %s", libusb_error_name(err));
		return false;
	}

	return true;
}

struct mpsse_ctx *mpsse_open(const uint16_t vids[], const uint16_t pids[], const char *description,
	const char *serial, const char *location, int channel)
{
	struct mpsse_ctx *ctx = calloc(1, sizeof(*ctx));
	int err;

	if (!ctx)
		return NULL;

	bit_copy_queue_init(&ctx->read_queue);
	ctx->read_chunk_size = 16384;
	ctx->read_size = 16384;
	ctx->write_size = 16384;
	ctx->read_chunk = malloc(ctx->read_chunk_size);
	ctx->read_buffer = malloc(ctx->read_size);

	/* Use calloc to make valgrind happy: buffer_write() sets payload
	 * on bit basis, so some bits can be left uninitialized in write_buffer.
	 * Although this is perfectly ok with MPSSE, valgrind reports
	 * Syscall param ioctl(USBDEVFS_SUBMITURB).buffer points to uninitialised byte(s) */
	ctx->write_buffer = calloc(1, ctx->write_size);

	if (!ctx->read_chunk || !ctx->read_buffer || !ctx->write_buffer)
		goto error;

	ctx->interface = channel;
	ctx->index = channel + 1;
	ctx->usb_read_timeout = 5000;
	ctx->usb_write_timeout = 5000;

	err = libusb_init(&ctx->usb_ctx);
	if (err != LIBUSB_SUCCESS) {
		LOG_ERROR("libusb_init() failed with %s", libusb_error_name(err));
		goto error;
	}

	if (!open_matching_device(ctx, vids, pids, description, serial, location)) {
		LOG_ERROR("unable to open ftdi device with description '%s', "
				"serial '%s' at bus location '%s'",
				description ? description : "*",
				serial ? serial : "*",
				location ? location : "*");
		ctx->usb_dev = NULL;
		goto error;
	}

	if (!mpsse_set_latency(ctx, 255)) {
		goto error;
	}

	if (!mpsse_set_bitmode(ctx, 0x0b)) {
		goto error;
	}

	mpsse_purge(ctx);

	return ctx;
error:
	mpsse_close(ctx);
	return NULL;
}

void mpsse_close(struct mpsse_ctx *ctx)
{
	if (ctx->usb_dev)
		libusb_close(ctx->usb_dev);
	if (ctx->usb_ctx)
		libusb_exit(ctx->usb_ctx);
#ifdef D2XX_SUPPORT
	if (ctx->d2xx_dev)
		d2xx.FT_Close(ctx->d2xx_dev);
#endif
	bit_copy_discard(&ctx->read_queue);

	free(ctx->write_buffer);
	free(ctx->read_buffer);
	free(ctx->read_chunk);
	free(ctx);
}

bool mpsse_is_high_speed(struct mpsse_ctx *ctx)
{
	return ctx->type != TYPE_FT2232C;
}

void mpsse_purge(struct mpsse_ctx *ctx)
{
	int err;
	LOG_DEBUG("-");
	ctx->write_count = 0;
	ctx->read_count = 0;
	ctx->retval = ERROR_OK;
	bit_copy_discard(&ctx->read_queue);

#ifdef D2XX_SUPPORT
	FT_STATUS status;
	if (ctx->d2xx_dev) {
		status = d2xx.FT_Purge(ctx->d2xx_dev, FT_PURGE_RX | FT_PURGE_TX);
		if (!FT_SUCCESS(status)) {
			LOG_ERROR("unable to purge ftdi buffers: %s", d2xx_error_name(status));
		}

		return;
	}
#endif

	err = libusb_control_transfer(ctx->usb_dev, FTDI_DEVICE_OUT_REQTYPE, SIO_RESET_REQUEST,
			SIO_RESET_PURGE_RX, ctx->index, NULL, 0, ctx->usb_write_timeout);
	if (err < 0) {
		LOG_ERROR("unable to purge ftdi rx buffers: %s", libusb_error_name(err));
		return;
	}

	err = libusb_control_transfer(ctx->usb_dev, FTDI_DEVICE_OUT_REQTYPE, SIO_RESET_REQUEST,
			SIO_RESET_PURGE_TX, ctx->index, NULL, 0, ctx->usb_write_timeout);
	if (err < 0) {
		LOG_ERROR("unable to purge ftdi tx buffers: %s", libusb_error_name(err));
		return;
	}
}

static unsigned buffer_write_space(struct mpsse_ctx *ctx)
{
	/* Reserve one byte for SEND_IMMEDIATE */
	return ctx->write_size - ctx->write_count - 1;
}

static unsigned buffer_read_space(struct mpsse_ctx *ctx)
{
	return ctx->read_size - ctx->read_count;
}

static void buffer_write_byte(struct mpsse_ctx *ctx, uint8_t data)
{
	LOG_DEBUG_IO("%02x", data);
	assert(ctx->write_count < ctx->write_size);
	ctx->write_buffer[ctx->write_count++] = data;
}

static unsigned buffer_write(struct mpsse_ctx *ctx, const uint8_t *out, unsigned out_offset,
	unsigned bit_count)
{
	LOG_DEBUG_IO("%d bits", bit_count);
	assert(ctx->write_count + DIV_ROUND_UP(bit_count, 8) <= ctx->write_size);
	bit_copy(ctx->write_buffer + ctx->write_count, 0, out, out_offset, bit_count);
	ctx->write_count += DIV_ROUND_UP(bit_count, 8);
	return bit_count;
}

static unsigned buffer_add_read(struct mpsse_ctx *ctx, uint8_t *in, unsigned in_offset,
	unsigned bit_count, unsigned offset)
{
	LOG_DEBUG_IO("%d bits, offset %d", bit_count, offset);
	assert(ctx->read_count + DIV_ROUND_UP(bit_count, 8) <= ctx->read_size);
	bit_copy_queued(&ctx->read_queue, in, in_offset, ctx->read_buffer + ctx->read_count, offset,
		bit_count);
	ctx->read_count += DIV_ROUND_UP(bit_count, 8);
	return bit_count;
}

void mpsse_clock_data_out(struct mpsse_ctx *ctx, const uint8_t *out, unsigned out_offset,
	unsigned length, uint8_t mode)
{
	mpsse_clock_data(ctx, out, out_offset, NULL, 0, length, mode);
}

void mpsse_clock_data_in(struct mpsse_ctx *ctx, uint8_t *in, unsigned in_offset, unsigned length,
	uint8_t mode)
{
	mpsse_clock_data(ctx, NULL, 0, in, in_offset, length, mode);
}

void mpsse_clock_data(struct mpsse_ctx *ctx, const uint8_t *out, unsigned out_offset, uint8_t *in,
	unsigned in_offset, unsigned length, uint8_t mode)
{
	/* TODO: Fix MSB first modes */
	LOG_DEBUG_IO("%s%s %d bits", in ? "in" : "", out ? "out" : "", length);

	if (ctx->retval != ERROR_OK) {
		LOG_DEBUG_IO("Ignoring command due to previous error");
		return;
	}

	/* TODO: On H chips, use command 0x8E/0x8F if in and out are both 0 */
	if (out || (!out && !in))
		mode |= 0x10;
	if (in)
		mode |= 0x20;

	while (length > 0) {
		/* Guarantee buffer space enough for a minimum size transfer */
		if (buffer_write_space(ctx) + (length < 8) < (out || (!out && !in) ? 4 : 3)
				|| (in && buffer_read_space(ctx) < 1))
			ctx->retval = mpsse_flush(ctx);

		if (length < 8) {
			/* Transfer remaining bits in bit mode */
			buffer_write_byte(ctx, 0x02 | mode);
			buffer_write_byte(ctx, length - 1);
			if (out)
				out_offset += buffer_write(ctx, out, out_offset, length);
			if (in)
				in_offset += buffer_add_read(ctx, in, in_offset, length, 8 - length);
			if (!out && !in)
				buffer_write_byte(ctx, 0x00);
			length = 0;
		} else {
			/* Byte transfer */
			unsigned this_bytes = length / 8;
			/* MPSSE command limit */
			if (this_bytes > 65536)
				this_bytes = 65536;
			/* Buffer space limit. We already made sure there's space for the minimum
			 * transfer. */
			if ((out || (!out && !in)) && this_bytes + 3 > buffer_write_space(ctx))
				this_bytes = buffer_write_space(ctx) - 3;
			if (in && this_bytes > buffer_read_space(ctx))
				this_bytes = buffer_read_space(ctx);

			if (this_bytes > 0) {
				buffer_write_byte(ctx, mode);
				buffer_write_byte(ctx, (this_bytes - 1) & 0xff);
				buffer_write_byte(ctx, (this_bytes - 1) >> 8);
				if (out)
					out_offset += buffer_write(ctx,
							out,
							out_offset,
							this_bytes * 8);
				if (in)
					in_offset += buffer_add_read(ctx,
							in,
							in_offset,
							this_bytes * 8,
							0);
				if (!out && !in)
					for (unsigned n = 0; n < this_bytes; n++)
						buffer_write_byte(ctx, 0x00);
				length -= this_bytes * 8;
			}
		}
	}
}

void mpsse_clock_tms_cs_out(struct mpsse_ctx *ctx, const uint8_t *out, unsigned out_offset,
	unsigned length, bool tdi, uint8_t mode)
{
	mpsse_clock_tms_cs(ctx, out, out_offset, NULL, 0, length, tdi, mode);
}

void mpsse_clock_tms_cs(struct mpsse_ctx *ctx, const uint8_t *out, unsigned out_offset, uint8_t *in,
	unsigned in_offset, unsigned length, bool tdi, uint8_t mode)
{
	LOG_DEBUG_IO("%sout %d bits, tdi=%d", in ? "in" : "", length, tdi);
	assert(out);

	if (ctx->retval != ERROR_OK) {
		LOG_DEBUG_IO("Ignoring command due to previous error");
		return;
	}

	mode |= 0x42;
	if (in)
		mode |= 0x20;

	while (length > 0) {
		/* Guarantee buffer space enough for a minimum size transfer */
		if (buffer_write_space(ctx) < 3 || (in && buffer_read_space(ctx) < 1))
			ctx->retval = mpsse_flush(ctx);

		/* Byte transfer */
		unsigned this_bits = length;
		/* MPSSE command limit */
		/* NOTE: there's a report of an FT2232 bug in this area, where shifting
		 * exactly 7 bits can make problems with TMS signaling for the last
		 * clock cycle:
		 *
		 * http://developer.intra2net.com/mailarchive/html/libftdi/2009/msg00292.html
		 */
		if (this_bits > 7)
			this_bits = 7;

		if (this_bits > 0) {
			buffer_write_byte(ctx, mode);
			buffer_write_byte(ctx, this_bits - 1);
			uint8_t data = 0;
			/* TODO: Fix MSB first, if allowed in MPSSE */
			bit_copy(&data, 0, out, out_offset, this_bits);
			out_offset += this_bits;
			buffer_write_byte(ctx, data | (tdi ? 0x80 : 0x00));
			if (in)
				in_offset += buffer_add_read(ctx,
						in,
						in_offset,
						this_bits,
						8 - this_bits);
			length -= this_bits;
		}
	}
}

void mpsse_set_data_bits_low_byte(struct mpsse_ctx *ctx, uint8_t data, uint8_t dir)
{
	LOG_DEBUG_IO("-");

	if (ctx->retval != ERROR_OK) {
		LOG_DEBUG_IO("Ignoring command due to previous error");
		return;
	}

	if (buffer_write_space(ctx) < 3)
		ctx->retval = mpsse_flush(ctx);

	buffer_write_byte(ctx, 0x80);
	buffer_write_byte(ctx, data);
	buffer_write_byte(ctx, dir);
}

void mpsse_set_data_bits_high_byte(struct mpsse_ctx *ctx, uint8_t data, uint8_t dir)
{
	LOG_DEBUG_IO("-");

	if (ctx->retval != ERROR_OK) {
		LOG_DEBUG_IO("Ignoring command due to previous error");
		return;
	}

	if (buffer_write_space(ctx) < 3)
		ctx->retval = mpsse_flush(ctx);

	buffer_write_byte(ctx, 0x82);
	buffer_write_byte(ctx, data);
	buffer_write_byte(ctx, dir);
}

void mpsse_read_data_bits_low_byte(struct mpsse_ctx *ctx, uint8_t *data)
{
	LOG_DEBUG_IO("-");

	if (ctx->retval != ERROR_OK) {
		LOG_DEBUG_IO("Ignoring command due to previous error");
		return;
	}

	if (buffer_write_space(ctx) < 1 || buffer_read_space(ctx) < 1)
		ctx->retval = mpsse_flush(ctx);

	buffer_write_byte(ctx, 0x81);
	buffer_add_read(ctx, data, 0, 8, 0);
}

void mpsse_read_data_bits_high_byte(struct mpsse_ctx *ctx, uint8_t *data)
{
	LOG_DEBUG_IO("-");

	if (ctx->retval != ERROR_OK) {
		LOG_DEBUG_IO("Ignoring command due to previous error");
		return;
	}

	if (buffer_write_space(ctx) < 1 || buffer_read_space(ctx) < 1)
		ctx->retval = mpsse_flush(ctx);

	buffer_write_byte(ctx, 0x83);
	buffer_add_read(ctx, data, 0, 8, 0);
}

static void single_byte_boolean_helper(struct mpsse_ctx *ctx, bool var, uint8_t val_if_true,
	uint8_t val_if_false)
{
	if (ctx->retval != ERROR_OK) {
		LOG_DEBUG_IO("Ignoring command due to previous error");
		return;
	}

	if (buffer_write_space(ctx) < 1)
		ctx->retval = mpsse_flush(ctx);

	buffer_write_byte(ctx, var ? val_if_true : val_if_false);
}

void mpsse_loopback_config(struct mpsse_ctx *ctx, bool enable)
{
	LOG_DEBUG("%s", enable ? "on" : "off");
	single_byte_boolean_helper(ctx, enable, 0x84, 0x85);
}

void mpsse_set_divisor(struct mpsse_ctx *ctx, uint16_t divisor)
{
	LOG_DEBUG("%d", divisor);

	if (ctx->retval != ERROR_OK) {
		LOG_DEBUG_IO("Ignoring command due to previous error");
		return;
	}

	if (buffer_write_space(ctx) < 3)
		ctx->retval = mpsse_flush(ctx);

	buffer_write_byte(ctx, 0x86);
	buffer_write_byte(ctx, divisor & 0xff);
	buffer_write_byte(ctx, divisor >> 8);
}

int mpsse_divide_by_5_config(struct mpsse_ctx *ctx, bool enable)
{
	if (!mpsse_is_high_speed(ctx))
		return ERROR_FAIL;

	LOG_DEBUG("%s", enable ? "on" : "off");
	single_byte_boolean_helper(ctx, enable, 0x8b, 0x8a);

	return ERROR_OK;
}

int mpsse_rtck_config(struct mpsse_ctx *ctx, bool enable)
{
	if (!mpsse_is_high_speed(ctx))
		return ERROR_FAIL;

	LOG_DEBUG("%s", enable ? "on" : "off");
	single_byte_boolean_helper(ctx, enable, 0x96, 0x97);

	return ERROR_OK;
}

int mpsse_set_frequency(struct mpsse_ctx *ctx, int frequency)
{
	LOG_DEBUG("target %d Hz", frequency);
	assert(frequency >= 0);
	int base_clock;

	if (frequency == 0)
		return mpsse_rtck_config(ctx, true);

	mpsse_rtck_config(ctx, false); /* just try */

	if (frequency > 60000000 / 2 / 65536 && mpsse_divide_by_5_config(ctx, false) == ERROR_OK) {
		base_clock = 60000000;
	} else {
		mpsse_divide_by_5_config(ctx, true); /* just try */
		base_clock = 12000000;
	}

	int divisor = (base_clock / 2 + frequency - 1) / frequency - 1;
	if (divisor > 65535)
		divisor = 65535;
	assert(divisor >= 0);

	mpsse_set_divisor(ctx, divisor);

	frequency = base_clock / 2 / (1 + divisor);
	LOG_DEBUG("actually %d Hz", frequency);

	return frequency;
}

/* Context needed by the callbacks */
struct transfer_result {
	struct mpsse_ctx *ctx;
	bool done;
	unsigned transferred;
};

static LIBUSB_CALL void read_cb(struct libusb_transfer *transfer)
{
	struct transfer_result *res = transfer->user_data;
	struct mpsse_ctx *ctx = res->ctx;

	unsigned packet_size = ctx->max_packet_size;

	DEBUG_PRINT_BUF(transfer->buffer, transfer->actual_length);

	/* Strip the two status bytes sent at the beginning of each USB packet
	 * while copying the chunk buffer to the read buffer */
	unsigned num_packets = DIV_ROUND_UP(transfer->actual_length, packet_size);
	unsigned chunk_remains = transfer->actual_length;
	for (unsigned i = 0; i < num_packets && chunk_remains > 2; i++) {
		unsigned this_size = packet_size - 2;
		if (this_size > chunk_remains - 2)
			this_size = chunk_remains - 2;
		if (this_size > ctx->read_count - res->transferred)
			this_size = ctx->read_count - res->transferred;
		memcpy(ctx->read_buffer + res->transferred,
			ctx->read_chunk + packet_size * i + 2,
			this_size);
		res->transferred += this_size;
		chunk_remains -= this_size + 2;
		if (res->transferred == ctx->read_count) {
			res->done = true;
			break;
		}
	}

	LOG_DEBUG_IO("raw chunk %d, transferred %d of %d", transfer->actual_length, res->transferred,
		ctx->read_count);

	if (!res->done)
		if (libusb_submit_transfer(transfer) != LIBUSB_SUCCESS)
			res->done = true;
}

static LIBUSB_CALL void write_cb(struct libusb_transfer *transfer)
{
	struct transfer_result *res = transfer->user_data;
	struct mpsse_ctx *ctx = res->ctx;

	res->transferred += transfer->actual_length;

	LOG_DEBUG_IO("transferred %d of %d", res->transferred, ctx->write_count);

	DEBUG_PRINT_BUF(transfer->buffer, transfer->actual_length);

	if (res->transferred == ctx->write_count)
		res->done = true;
	else {
		transfer->length = ctx->write_count - res->transferred;
		transfer->buffer = ctx->write_buffer + res->transferred;
		if (libusb_submit_transfer(transfer) != LIBUSB_SUCCESS)
			res->done = true;
	}
}

#ifdef D2XX_SUPPORT
static int mpsse_flush_d2xx(struct mpsse_ctx *ctx)
{
	FT_STATUS status;
	DWORD written;
	DWORD read;
	DWORD total_written = 0;
	DWORD total_read = 0;
	int retval = ctx->retval;

	if (ctx->read_count) {
		buffer_write_byte(ctx, 0x87); /* SEND_IMMEDIATE */
		/* delay read transaction to ensure the FTDI chip can support us with data
		   immediately after processing the MPSSE commands in the write transaction */
	}

	while (total_written < ctx->write_count &&
			FT_SUCCESS(status = d2xx.FT_Write(ctx->d2xx_dev, &ctx->write_buffer[total_written],
			ctx->write_count - total_written, &written))) {

		total_written += written;
		assert(total_written <= ctx->write_count);

		LOG_DEBUG_IO("transferred %d of %d", (int)total_written, ctx->write_count);

		DEBUG_PRINT_BUF((&ctx->write_buffer[total_written-written]), ((int)written));
	}

	if (!FT_SUCCESS(status))
		goto error_check;

	// short circuits if ctx->read_count == 0
	while (total_read < ctx->read_count &&
			FT_SUCCESS(status = d2xx.FT_Read(ctx->d2xx_dev, &ctx->read_buffer[total_read],
			ctx->read_count - total_read, &read))) {

		total_read += read;
		assert(total_read <= ctx->read_count);

		LOG_DEBUG_IO("read %d of %d", (int)total_read, ctx->read_count);

		DEBUG_PRINT_BUF((&ctx->read_buffer[total_read-read]), ((int)read));
	}

error_check:
	if (!FT_SUCCESS(status)) {
		LOG_ERROR("mpsse_flush_d2xx() failed with %s", d2xx_error_name(status));
		retval = ERROR_FAIL;
	} else if (total_written < ctx->write_count) {
		LOG_ERROR("ftdi device did not accept all data: %d, tried %d",
			(int)total_written,
			ctx->write_count);
		retval = ERROR_FAIL;
	} else if (total_read < ctx->read_count) {
		LOG_ERROR("ftdi device did not return all data: %d, expected %d",
			(int)total_read,
			ctx->read_count);
		retval = ERROR_FAIL;
	} else if (ctx->read_count) {
		ctx->write_count = 0;
		ctx->read_count = 0;
		bit_copy_execute(&ctx->read_queue);
		retval = ERROR_OK;
	} else {
		ctx->write_count = 0;
		bit_copy_discard(&ctx->read_queue);
		retval = ERROR_OK;
	}

	if (retval != ERROR_OK)
		mpsse_purge(ctx);

	return retval;
}
#endif

int mpsse_flush(struct mpsse_ctx *ctx)
{
	int retval = ctx->retval;

	if (retval != ERROR_OK) {
		LOG_DEBUG_IO("Ignoring flush due to previous error");
		assert(ctx->write_count == 0 && ctx->read_count == 0);
		ctx->retval = ERROR_OK;
		return retval;
	}

	LOG_DEBUG_IO("write %d%s, read %d", ctx->write_count, ctx->read_count ? "+1" : "",
			ctx->read_count);
	assert(ctx->write_count > 0 || ctx->read_count == 0); /* No read data without write data */

	if (ctx->write_count == 0)
		return retval;

#ifdef D2XX_SUPPORT
	if (ctx->d2xx_dev) {
		return mpsse_flush_d2xx(ctx);
	}
#endif

	struct libusb_transfer *read_transfer = NULL;
	struct transfer_result read_result = { .ctx = ctx, .done = true };
	if (ctx->read_count) {
		buffer_write_byte(ctx, 0x87); /* SEND_IMMEDIATE */
		read_result.done = false;
		/* delay read transaction to ensure the FTDI chip can support us with data
		   immediately after processing the MPSSE commands in the write transaction */
	}

	struct transfer_result write_result = { .ctx = ctx, .done = false };
	struct libusb_transfer *write_transfer = libusb_alloc_transfer(0);
	libusb_fill_bulk_transfer(write_transfer, ctx->usb_dev, ctx->out_ep, ctx->write_buffer,
		ctx->write_count, write_cb, &write_result, ctx->usb_write_timeout);
	retval = libusb_submit_transfer(write_transfer);
	if (retval != LIBUSB_SUCCESS)
		goto error_check;

	if (ctx->read_count) {
		read_transfer = libusb_alloc_transfer(0);
		libusb_fill_bulk_transfer(read_transfer, ctx->usb_dev, ctx->in_ep, ctx->read_chunk,
			ctx->read_chunk_size, read_cb, &read_result,
			ctx->usb_read_timeout);
		retval = libusb_submit_transfer(read_transfer);
		if (retval != LIBUSB_SUCCESS)
			goto error_check;
	}

	/* Polling loop, more or less taken from libftdi */
	int64_t start = timeval_ms();
	int64_t warn_after = 2000;
	while (!write_result.done || !read_result.done) {
		struct timeval timeout_usb;

		timeout_usb.tv_sec = 1;
		timeout_usb.tv_usec = 0;

		retval = libusb_handle_events_timeout_completed(ctx->usb_ctx, &timeout_usb, NULL);
		keep_alive();
		if (retval == LIBUSB_ERROR_NO_DEVICE || retval == LIBUSB_ERROR_INTERRUPTED)
			break;

		if (retval != LIBUSB_SUCCESS) {
			libusb_cancel_transfer(write_transfer);
			if (read_transfer)
				libusb_cancel_transfer(read_transfer);
			while (!write_result.done || !read_result.done) {
				retval = libusb_handle_events_timeout_completed(ctx->usb_ctx,
								&timeout_usb, NULL);
				if (retval != LIBUSB_SUCCESS)
					break;
			}
		}

		int64_t now = timeval_ms();
		if (now - start > warn_after) {
			LOG_WARNING("Haven't made progress in mpsse_flush() for %" PRId64
					"ms.", now - start);
			warn_after *= 2;
		}
	}

error_check:
	if (retval != LIBUSB_SUCCESS) {
		LOG_ERROR("libusb_handle_events() failed with %s", libusb_error_name(retval));
		retval = ERROR_FAIL;
	} else if (write_result.transferred < ctx->write_count) {
		LOG_ERROR("ftdi device did not accept all data: %d, tried %d",
			write_result.transferred,
			ctx->write_count);
		retval = ERROR_FAIL;
	} else if (read_result.transferred < ctx->read_count) {
		LOG_ERROR("ftdi device did not return all data: %d, expected %d",
			read_result.transferred,
			ctx->read_count);
		retval = ERROR_FAIL;
	} else if (ctx->read_count) {
		ctx->write_count = 0;
		ctx->read_count = 0;
		bit_copy_execute(&ctx->read_queue);
		retval = ERROR_OK;
	} else {
		ctx->write_count = 0;
		bit_copy_discard(&ctx->read_queue);
		retval = ERROR_OK;
	}

	if (retval != ERROR_OK)
		mpsse_purge(ctx);

	libusb_free_transfer(write_transfer);
	if (read_transfer)
		libusb_free_transfer(read_transfer);

	return retval;
}
