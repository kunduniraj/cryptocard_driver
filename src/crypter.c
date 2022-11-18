#include "crypter.h"
#include <sys/ioctl.h>
#include <sys/mman.h>

#define SET_KEY  _IOW(243, 1, struct cc_key)
#define SET_CONFIG  _IOW(243, 2, struct cc_config)
#define ENCRYPT  _IOW(243, 3, struct cc_op *)
#define DECRYPT  _IOW(243, 4, struct cc_op *)

static uint64_t map_size;

struct cc_key {
    uint8_t a;
    uint8_t b;
};

struct cc_config {
    uint8_t mode_int_dma; // 0 = Interrupt and 1 = DMA
    uint8_t set;
};

struct cc_op {
	void * addr;
	uint64_t length;
	uint8_t isMapped;
};
	
/*Function template to create handle for the CryptoCard device.
On success it returns the device handle as an integer*/
DEV_HANDLE create_handle()
{
	int fd;

	fd = open("/dev/cryptocard",O_RDWR);
	if (fd < 0) {
		perror("open");
		return ERROR;
	}  

	return fd;
}

/*Function template to close device handle.
Takes an already opened device handle as an arguments*/
void close_handle(DEV_HANDLE cdev)
{
	close(cdev);
}

/*Function template to encrypt a message using MMIO/DMA/Memory-mapped.
Takes four arguments
  cdev: opened device handle
  addr: data address on which encryption has to be performed
  length: size of data to be encrypt
  isMapped: TRUE if addr is memory-mapped address otherwise FALSE
*/
int encrypt(DEV_HANDLE cdev, ADDR_PTR addr, uint64_t length, uint8_t isMapped)
{
	struct cc_op ccop;
    int err;

	if(length <= 32000) {
    	ccop.addr = addr;
    	ccop.length = length;
		ccop.isMapped = isMapped;

    	err = ioctl(cdev,ENCRYPT, &ccop);
    	if (err == -1)
        	return ERROR;
	
	    return err;
	}
	else
	{
		int count, residual, chunk = 32000;
		char *new = (char *)addr;

		count = length/chunk;
		residual =  length%chunk;
		
		ccop.isMapped = isMapped;
		for(int i=0;i<count;i++){
    		ccop.addr = new;
    		ccop.length = chunk ;
			err = ioctl(cdev,ENCRYPT, &ccop);
	        if (err == -1)
    	        return ERROR;
			new = new + chunk;
		}
		if(residual != 0){
            ccop.addr = new;
            ccop.length = residual ;
            err = ioctl(cdev,ENCRYPT, &ccop);
            if (err == -1)
                return ERROR;

		}
        return err;
	}						
}	


/*Function template to decrypt a message using MMIO/DMA/Memory-mapped.
Takes four arguments
  cdev: opened device handle
  addr: data address on which decryption has to be performed
  length: size of data to be decrypt
  isMapped: TRUE if addr is memory-mapped address otherwise FALSE
*/
int decrypt(DEV_HANDLE cdev, ADDR_PTR addr, uint64_t length, uint8_t isMapped)
{
	struct cc_op ccop;
    int err;
    
	if(length <= 32768) {
    	ccop.addr = addr;
    	ccop.length = length;
		ccop.isMapped = isMapped;
    
   		err = ioctl(cdev,DECRYPT, &ccop);
    	if (err == -1)
        	return ERROR;
    
    	return err;
	}
	else
    {
        int count, residual, chunk = 32768;
        char *new = (char *)addr;

        count = length/chunk;
        residual =  length%chunk;

        ccop.isMapped = isMapped;
        for(int i=0;i<count;i++){
            ccop.addr = new;
            ccop.length = chunk ;
            err = ioctl(cdev,ENCRYPT, &ccop);
            if (err == -1)
                return ERROR;
            new = new + chunk;
        }
        if(residual != 0){
            ccop.addr = new;
            ccop.length = residual ;
            err = ioctl(cdev,ENCRYPT, &ccop);
            if (err == -1)
                return ERROR;

        }
        return err;
    }

}

/*Function template to set the key pair.
Takes three arguments
  cdev: opened device handle
  a: value of key component a
  b: value of key component b
Return 0 in case of key is set successfully*/
int set_key(DEV_HANDLE cdev, KEY_COMP a, KEY_COMP b)
{
	struct cc_key cckey;
	int err;	

	cckey.a = a;
	cckey.b = b;

	err = ioctl(cdev,SET_KEY, &cckey);
	if (err == -1)
  		return ERROR;
	
	return err;
}

/*Function template to set configuration of the device to operate.
Takes three arguments
  cdev: opened device handle
  type: type of configuration, i.e. set/unset DMA operation, interrupt
  value: SET/UNSET to enable or disable configuration as described in type
Return 0 in case of key is set successfully*/
int set_config(DEV_HANDLE cdev, config_t type, uint8_t value)
{
    struct cc_config config;
    int err;

    config.mode_int_dma = type;
    config.set = value;
    err = ioctl(cdev,SET_CONFIG, &config);
    if (err == -1)
        return ERROR;

    return err;

}

/*Function template to device input/output memory into user space.
Takes three arguments
  cdev: opened device handle
  size: amount of memory-mapped into user-space (not more than 1MB strict check)
Return virtual address of the mapped memory*/
ADDR_PTR map_card(DEV_HANDLE cdev, uint64_t size)
{
	 
	if(size <= (0x100000-0xa8)) {
 		ADDR_PTR addr = mmap(NULL, size+0xa8, PROT_READ|PROT_WRITE, MAP_SHARED, cdev, 0);

		printf("inside map_card function\n");	
		if(addr == MAP_FAILED) {
			printf("mmap failed in map_card function \n");	
			return NULL;
		}
	
		map_size = size;
		addr = ((uint8_t *)addr) + 0xa8;		

		return addr;
	}
	else
		return NULL;
		
}

/*Function template to device input/output memory into user space.
Takes three arguments
  cdev: opened device handle
  addr: memory-mapped address to unmap from user-space*/
void unmap_card(DEV_HANDLE cdev, ADDR_PTR addr)
{
	addr = ((uint8_t *)addr) - 0xa8;
	
	munmap(addr, map_size);
}
