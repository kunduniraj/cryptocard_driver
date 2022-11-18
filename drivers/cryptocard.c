#include <linux/pci.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/dma-mapping.h>
#include <linux/ioctl.h>

#define DRIVER_NAME "cryptocard"
#define LIVE_OFF 0x4
#define KEY_OFF 0x8
#define B_OFF 0xb
#define MMDATA_LEN_OFF 0xc
#define MMSTATUS_OFF 0x20
#define INT_STATUS_OFF 0x24
#define INT_ACK_OFF 0x64
#define MMADDR_OFF 0x80
#define DMA_ADDR_OFF 0x90
#define DMA_DATA_LEN_OFF 0x98
#define DMA_CMD_OFF 0xa0
#define DATA_OFF 0xa8

#define SET_KEY  _IOW(243, 1, struct cc_key)
#define SET_CONFIG  _IOW(243, 2, struct cc_config)
#define ENCRYPT  _IOW(243, 3, struct cc_op *)
#define DECRYPT  _IOW(243, 4, struct cc_op *)

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

struct cryptocard_config {
	uint8_t a;
	uint8_t b;
	uint8_t dma;
	uint8_t interrupt;
	uint8_t isKeyset;
	uint8_t isConfigset;
};
//static struct cryptocard_config l_config; // kmalloc(sizeof(struct cryptocard_config), GFP_KERNEL);

static int major;
atomic_t  device_opened;
static struct class *cc_class;
struct device *cc_device;

DEFINE_SPINLOCK(cc_spinlock);

static struct pci_device_id cryptocard_id_table[] = {
    { PCI_DEVICE(0x1234, 0xDEBA) },
    { 0, }
};

MODULE_DEVICE_TABLE(pci, cryptocard_id_table);

static int cryptocard_probe(struct pci_dev *pdev, const struct pci_device_id *ent);
static void cryptocard_remove(struct pci_dev *pdev);

/* Driver structure : pci_driver  */
static struct pci_driver cryptocard = {
    .name = DRIVER_NAME,
    .id_table = cryptocard_id_table,
    .probe = cryptocard_probe,
    .remove = cryptocard_remove
};

struct cryptocard_mm {
	struct pci_dev *pdev;
	u8 __iomem *ccbar0;	// for mapping bar0 memory space to driver virtual address space, without mapping it would be difficult
	unsigned long mmio_start;
};

static struct cryptocard_mm cc_info;

DECLARE_WAIT_QUEUE_HEAD(cc_wq);
int wq_flag = 0;

static int  cryptocard_entry(void) 
{
    printk(KERN_INFO "%s: entry test\n",__FILE__);
	return pci_register_driver(&cryptocard);
}

static void cryptocard_exit(void) {
    printk(KERN_INFO "%s: exiting...\n",__FILE__);
	pci_unregister_driver(&cryptocard);
}


/////////////////////////////////////////////   functions   ///////////////////////////////////////////////////


void decryption_mmap_polling(/*struct pci_dev *pdev*/u64 length)
{
    u8 __iomem *ccbar0 = cc_info.ccbar0;
    //u8 __iomem *temp = NULL;
    u32 len;
    //char *readdata;

    len = (u32)length;
    //setting operation: decryption with polling - bit1 = 1 (decryption) and bit7 = 0 (with polling)
    iowrite32(0x00000002, ccbar0+MMSTATUS_OFF);
    //memcpy_toio(ccbar0 + DATA_OFF, data, len);
    iowrite32(len, ccbar0 + MMDATA_LEN_OFF);

    //readdata = kmalloc(len+1,GFP_KERNEL);
    //memcpy_fromio(readdata, ccbar0 + DATA_OFF, len);
    //readdata[len] = '\0';

    //printk(KERN_INFO "Memory Status Register = 0x%08x, Encrypted Text=%s\n", ioread32(ccbar0+MMSTATUS_OFF), readdata);
    printk(KERN_INFO "Text len:%u\n", ioread32(ccbar0+MMDATA_LEN_OFF));

    while((ioread32(ccbar0+MMSTATUS_OFF) & 1)) ;

    printk(KERN_INFO "Device is free...Starting DEOP.\n");
    iowrite32((u32)0xa8, ccbar0+MMADDR_OFF);        // below one also working

    while(ioread32(ccbar0+MMSTATUS_OFF) & 1);

    //memcpy_fromio(readdata, ccbar0 + DATA_OFF, len);
    //readdata[len] = '\0';
    //printk(KERN_INFO "Decrypted string is: %s\n", readdata);

    //kfree(readdata);
}


void encryption_mmap_polling(/*struct pci_dev *pdev*/u64 length)
{
    u8 __iomem *ccbar0 = cc_info.ccbar0;
    //u8 __iomem *temp = NULL;
    u32 len;
	//char *readdata;

    len = (u32)length;
    //setting operation: encryption with polling - bit1 = 0 (encryption) and bit7 = 0 (with polling)
    iowrite32(0x00000000, ccbar0+MMSTATUS_OFF);
    //memcpy_toio(ccbar0 + DATA_OFF, data, len);
    iowrite32(len, ccbar0 + MMDATA_LEN_OFF);

    //readdata = kmalloc(len+1,GFP_KERNEL);
    //memcpy_fromio(readdata, ccbar0 + DATA_OFF, len);
    //readdata[len] = '\0';

    //printk(KERN_INFO "Memory Status Register = 0x%08x, Plain Text=%s\n", ioread32(ccbar0+MMSTATUS_OFF), readdata);
    printk(KERN_INFO "Text len:%u\n", ioread32(ccbar0+MMDATA_LEN_OFF));

    while((ioread32(ccbar0+MMSTATUS_OFF) & 1)) ;

    printk(KERN_INFO "Device is free...Starting ENOP.\n");
    iowrite32((u32)0xa8, ccbar0+MMADDR_OFF);        // below one also working

    while(ioread32(ccbar0+MMSTATUS_OFF) & 1);

    //memcpy_fromio(readdata, ccbar0 + DATA_OFF, len);
    // readdata[len] = '\0';
    //printk(KERN_INFO "Encrypted string is: %s\n", readdata);
	
	//kfree(readdata);
}

static irqreturn_t cryptocard_irq_handle(int irq, void * pdev)
{
    struct cryptocard_mm *cc_mmregion = pci_get_drvdata((struct pci_dev *)pdev);
    u8 __iomem *ccbar0 = cc_mmregion->ccbar0;
	u32 istatus;
	//char readdata[16];
	
    istatus = ioread32(ccbar0+INT_STATUS_OFF);
    iowrite32(istatus, ccbar0+INT_ACK_OFF);
	

    //memcpy_fromio(readdata, ccbar0 + DATA_OFF, 12);
    //readdata[12] = '\0';
    //printk(KERN_INFO "inside interrupt Encrypted string is: %s\n", readdata);

	wq_flag = 1;
	wake_up_interruptible(&cc_wq);
	
	printk("IRQ handled ...\n");
	
	return IRQ_HANDLED;
}

void encryption_mmap_interrupt(/*struct pci_dev *pdev*/u64 length)
{
    u8 __iomem *ccbar0 = cc_info.ccbar0;
    u32 len;
    //char *readdata;

    len = (u32)length;
    //setting operation: encryption with interrupt - bit1 = 0 (encryption) and bit7 = 1 (with interrupt)
    iowrite32(0x00000080, ccbar0+MMSTATUS_OFF);
    //memcpy_toio(ccbar0 + DATA_OFF, data, len);
    iowrite32(len, ccbar0 + MMDATA_LEN_OFF);

    //readdata = kmalloc(len+1,GFP_KERNEL);
    //memcpy_fromio(readdata, ccbar0 + DATA_OFF, len);
    //readdata[len] = '\0';

	pr_info("\nEncryption with MMAP and interrupt...\n");
    //printk(KERN_INFO "Memory Status Register = 0x%08x, Plain Text=%s\n", ioread32(ccbar0+MMSTATUS_OFF), readdata);
    printk(KERN_INFO "Text len:%u\n", ioread32(ccbar0+MMDATA_LEN_OFF));

    while((ioread32(ccbar0+MMSTATUS_OFF) & 1)) ;

    printk(KERN_INFO "Device is free...Starting ENOP.\n");
    iowrite32((u32)0xa8, ccbar0+MMADDR_OFF);        // below one also working
	
	wait_event_interruptible(cc_wq, wq_flag != 0);
    wq_flag = 0; 
    //while(ioread32(ccbar0+MMSTATUS_OFF) & 1);

    //memcpy_fromio(readdata, ccbar0 + DATA_OFF, len);
    //readdata[len] = '\0';
    //printk(KERN_INFO "Encrypted string is: %s\n", readdata);

    //kfree(readdata);
}

void decryption_mmap_interrupt(/*struct pci_dev *pdev*/u64 length)
{
    u8 __iomem *ccbar0 = cc_info.ccbar0;
    u32 len;
    //char *readdata;

    len = (u32)length;
    //setting operation: decryption with interrupt - bit1 = 1 (decryption) and bit7 = 1 (with interrupt)
    iowrite32(0x00000082, ccbar0+MMSTATUS_OFF);
    //memcpy_toio(ccbar0 + DATA_OFF, data, len);
    iowrite32(len, ccbar0 + MMDATA_LEN_OFF);

    //readdata = kmalloc(len+1,GFP_KERNEL);
    //memcpy_fromio(readdata, ccbar0 + DATA_OFF, len);
    //readdata[len] = '\0';

	pr_info("\nDecryption wiht MMAP and interrupt...\n");
    //printk(KERN_INFO "Memory Status Register = 0x%08x, Original Text=%s\n", ioread32(ccbar0+MMSTATUS_OFF), readdata);
    printk(KERN_INFO "Text len:%u\n", ioread32(ccbar0+MMDATA_LEN_OFF));

    while((ioread32(ccbar0+MMSTATUS_OFF) & 1)) ;

    printk(KERN_INFO "Device is free...Starting DEOP.\n");
    iowrite32((u32)0xa8, ccbar0+MMADDR_OFF);        // below one also working
    
    wait_event_interruptible(cc_wq, wq_flag != 0);
    wq_flag = 0; 
    //while(ioread32(ccbar0+MMSTATUS_OFF) & 1);

    //memcpy_fromio(readdata, ccbar0 + DATA_OFF, len);
    //readdata[len] = '\0';
    //printk(KERN_INFO "Decrypted string is: %s\n", readdata);

    //kfree(readdata);
}

void encryption_mmio_interrupt(char *data, u64 length)
{
    //struct pci_dev *pdev = cc_info.pdev;
    u8 __iomem *ccbar0 = cc_info.ccbar0;
    u32 len; // a=30, b=17;

    //char *readdata;
	
    len = (u32)length;
    //setting operation: encryption interrupt - bit1 = 0 (encryption) and bit7 = 1 (interrupt)
    iowrite32(0x00000080, ccbar0+MMSTATUS_OFF);
    memcpy_toio(ccbar0 + DATA_OFF, data, len);
    iowrite32(len, ccbar0 + MMDATA_LEN_OFF);

    //readdata = kmalloc(len+1,GFP_KERNEL);
    //memcpy_fromio(readdata, ccbar0 + DATA_OFF, len);
    //readdata[len] = '\0';

    //printk(KERN_INFO "Memory Status Register = 0x%08x, Plain Text=%s\n", ioread32(ccbar0+MMSTATUS_OFF), readdata);
    printk(KERN_INFO "Text len:%u\n", ioread32(ccbar0+MMDATA_LEN_OFF));

    while(ioread32(ccbar0+MMSTATUS_OFF) & 1) ;

    printk(KERN_INFO "Device is free...Starting ENOP.\n");
    iowrite32((u32)0xa8, ccbar0+MMADDR_OFF);       
   	
	wait_event_interruptible(cc_wq, wq_flag != 0);
	wq_flag = 0;	

    //memcpy_fromio(readdata, ccbar0 + DATA_OFF, len);
    //readdata[len] = '\0';
    //printk(KERN_INFO "Encrypted string is: %s\n", readdata);

	//kfree(readdata);
	memcpy_fromio(data, ccbar0 + DATA_OFF, len);
}

void decryption_mmio_interrupt(char *data, u64 length)
{
	//struct pci_dev *pdev = cc_info.pdev;
    u8 __iomem *ccbar0 = cc_info.ccbar0;
    u32 len; // a=30, b=17;
    
    //char *readdata;

    len = (u32)length;
    //setting operation: encryption interrupt - bit1 = 1 (decryption) and bit7 = 1 (interrupt)
    iowrite32(0x00000082, ccbar0+MMSTATUS_OFF);
    memcpy_toio(ccbar0 + DATA_OFF, data, len);
    iowrite32(len, ccbar0 + MMDATA_LEN_OFF);
    
    //readdata = kmalloc(len+1,GFP_KERNEL);
    //memcpy_fromio(readdata, ccbar0 + DATA_OFF, len);
    //readdata[len] = '\0';
    
	pr_info("Decryption with mmio and interrupt...\n");
    //printk(KERN_INFO "Memory Status Register = 0x%08x, Encrypted Text=%s\n", ioread32(ccbar0+MMSTATUS_OFF), readdata);
    printk(KERN_INFO "Text len:%u\n", ioread32(ccbar0+MMDATA_LEN_OFF));
    
    while(ioread32(ccbar0+MMSTATUS_OFF) & 1) ;

    printk(KERN_INFO "Device is free...Starting DEOP.\n");
    iowrite32((u32)0xa8, ccbar0+MMADDR_OFF);       
    
    wait_event_interruptible(cc_wq, wq_flag != 0);
    wq_flag = 0;    
    
    //memcpy_fromio(readdata, ccbar0 + DATA_OFF, len);
    //readdata[len] = '\0';
    //printk(KERN_INFO "Decrypted string is: %s\n", readdata);

    //kfree(readdata);
    memcpy_fromio(data, ccbar0 + DATA_OFF, len);
}

void encryption_dma_interrupt(char *data, u64 length)
{
    struct pci_dev *pdev = cc_info.pdev;
    u8 __iomem *ccbar0 = cc_info.ccbar0;
    dma_addr_t dma_handle;
    struct device *dev;
    u32 len;
    char *buff;

    len = (u32)length;
    dev = &pdev->dev;
    buff = dma_alloc_coherent(dev,len,&dma_handle,GFP_KERNEL);

    pr_info("\nEncryption with DMA and interrupt...\n");
    //printk(KERN_INFO "\nBuffer kernel virtual address = 0x%px\n", &(*buff));

    memcpy(buff,data,len);
    //buff[len] = '\0';
    //printk(KERN_INFO "Bufferd string(before ENOP): %s\n", buff);

    iowrite32(len, ccbar0+DMA_DATA_LEN_OFF);
    iowrite32(dma_handle, ccbar0+DMA_ADDR_OFF);

    printk(KERN_INFO "DMA handle returned: %llx\n",  dma_handle);

    while(ioread32(ccbar0+DMA_CMD_OFF) & 1) ;

    printk(KERN_INFO "Device is free...START OP\n");
    iowrite32(0x1|0x4, ccbar0+DMA_CMD_OFF);    //bit0 = 1 (DMA), bit1 = 0 (encryption), bit2 = 1 (with interrupt)

    wait_event_interruptible(cc_wq, wq_flag != 0);
    wq_flag = 0;    
    //while(ioread32(ccbar0+DMA_CMD_OFF) & 1);

    //data[len] = '\0';
    //printk(KERN_INFO "DMA address is(after ENOP): 0x%x\n", ioread32(ccbar0+DMA_ADDR_OFF));
    //printk(KERN_INFO "Original string is: %s\n", data);
	//printk(KERN_INFO "Buffered string (after encryption) is: %s\n", buff);
    //printk(KERN_INFO "DMA command register (after ENOP): 0x%x\n", ioread32(ccbar0+DMA_CMD_OFF));

    memcpy(data,buff,len);
    dma_free_coherent(dev,len,buff,dma_handle);
}

void decryption_dma_interrupt(char *data, u64 length)
{
    struct pci_dev *pdev = cc_info.pdev;
    u8 __iomem *ccbar0 = cc_info.ccbar0;
    dma_addr_t dma_handle;
    struct device *dev;
    u32 len;
    char *buff;

    len = (u32)length;
    dev = &pdev->dev;
    buff = dma_alloc_coherent(dev,len,&dma_handle,GFP_KERNEL);

    pr_info("\nDecryption with DMA and interrupt...\n");
    //printk(KERN_INFO "\nBuffer kernel virtual address = 0x%px\n", &(*buff));

    memcpy(buff,data,len);
    //buff[len] = '\0';
    //printk(KERN_INFO "Bufferd string(before DEOP): %s\n", buff);

    iowrite32(len, ccbar0+DMA_DATA_LEN_OFF);
    iowrite32(dma_handle, ccbar0+DMA_ADDR_OFF);

    printk(KERN_INFO "DMA handle returned: %llx\n",  dma_handle);

    while(ioread32(ccbar0+DMA_CMD_OFF) & 1) ;

    printk(KERN_INFO "Device is free...START DEOP\n");
    iowrite32(0x1|0x2|0x4, ccbar0+DMA_CMD_OFF);    //bit0 = 1 (DMA), bit1 = 1 (decryption), bit2 = 1 (with interrupt)

    wait_event_interruptible(cc_wq, wq_flag != 0);
    wq_flag = 0;
    //while(ioread32(ccbar0+DMA_CMD_OFF) & 1);

    //data[len] = '\0';
    //printk(KERN_INFO "DMA address is(after DEOP): 0x%x\n", ioread32(ccbar0+DMA_ADDR_OFF));
	//printk(KERN_INFO "Original string is: %s\n", data);
    //printk(KERN_INFO "Buffered string (after decryption) is: %s\n", buff);
    //printk(KERN_INFO "DMA command register (after DEOP): 0x%x\n", ioread32(ccbar0+DMA_CMD_OFF));

    memcpy(data,buff,len);
    dma_free_coherent(dev,len,buff,dma_handle);
}


void encryption_mmio_poll(/*struct pci_dev *pdev*/char *data, u64 length) 
{
	//struct cryptocard_mm *cc_mmregion = pci_get_drvdata(pdev);
	//u8 __iomem *ccbar0 = cc_mmregion->ccbar0;
	u8 __iomem *ccbar0 = cc_info.ccbar0;
	//u8 __iomem *temp = NULL;
	u32 len;

	//char /* *data = "Hello CS730!",*/ *readdata;
	//u32 len = strlen(data);

	len = (u32)length;	
	//setting operation: encryption without interrupt - bit1 = 0 (encryption) and bit7 = 0 (with polling)
	iowrite32(0x00000000, ccbar0+MMSTATUS_OFF);
	memcpy_toio(ccbar0 + DATA_OFF, data, len);
	iowrite32(len, ccbar0 + MMDATA_LEN_OFF);

	//readdata = kmalloc(len+1,GFP_KERNEL);
	//memcpy_fromio(readdata, ccbar0 + DATA_OFF, len);
	//readdata[len] = '\0';
	
	//printk(KERN_INFO "Memory Status Register = 0x%08x, Plain Text=%s\n", ioread32(ccbar0+MMSTATUS_OFF), readdata);
	printk(KERN_INFO "Text len:%u\n", ioread32(ccbar0+MMDATA_LEN_OFF));
	
	while(ioread32(ccbar0+MMSTATUS_OFF) & 1) ;

	printk(KERN_INFO "Device is free...Starting ENOP.\n");
	iowrite32((u32)0xa8, ccbar0+MMADDR_OFF);		// below one also working

	while(ioread32(ccbar0+MMSTATUS_OFF) & 1) ;

	//memcpy_fromio(readdata, ccbar0 + DATA_OFF, len);
	//readdata[len] = '\0';
	//printk(KERN_INFO "Encrypted string is: %s\n", readdata);

	//kfree(readdata);
	memcpy_fromio(data, ccbar0 + DATA_OFF, len);
}

void decryption_mmio_poll(/*struct pci_dev *pdev*/char *data, u64 length)
{
    //struct cryptocard_mm *cc_mmregion = pci_get_drvdata(pdev);
    //u8 __iomem *ccbar0 = cc_mmregion->ccbar0;
	u8 __iomem *ccbar0 = cc_info.ccbar0;
    //u8 __iomem *temp = NULL;
	u32 len;

    //char /* *data = "Czggj XN730!",*/ *readdata;
    //u32 len = strlen(data);

	len = (u32)length;
    iowrite32(len, ccbar0+MMDATA_LEN_OFF);
    //setting operation: decryption without interrupt - bit1 = 1 (decryption) and bit7 = 0 (with polling)
    iowrite32(0x00000002, ccbar0+MMSTATUS_OFF);
    
    memcpy_toio(ccbar0 + DATA_OFF, data, len);
	
	//readdata = kmalloc(len+1,GFP_KERNEL);
    //memcpy_fromio(readdata, ccbar0+DATA_OFF, len);
    //readdata[len] = '\0';

    //printk(KERN_INFO "Memory Status Register = 0x%08x, Original Text=%s\n", ioread32(ccbar0+MMSTATUS_OFF), readdata); 
    printk(KERN_INFO "Text len:%u\n",  ioread32(ccbar0+MMDATA_LEN_OFF));

	while(ioread32(ccbar0+MMSTATUS_OFF) & 1) ;
	
	printk(KERN_INFO "Device is free...START OP\n");
	iowrite32((u32)0xa8, ccbar0+MMADDR_OFF);        // below one also working
	
    while(ioread32(ccbar0+MMSTATUS_OFF) & 1) ;

	//memcpy_fromio(readdata, ccbar0 + DATA_OFF, len);
	//readdata[len] = '\0';
	//printk(KERN_INFO "Decrypted string is: %s\n", readdata);
	//kfree(readdata);
	
	memcpy_fromio(data, ccbar0 + DATA_OFF, len);
}

void encryption_dma_poll(char *data, u64 length)
{
    struct pci_dev *pdev = cc_info.pdev;
    u8 __iomem *ccbar0 = cc_info.ccbar0;
    dma_addr_t dma_handle;
    struct device *dev;
    u32 len;
    char *buff;

    len = (u32)length;
    dev = &pdev->dev;
    buff = dma_alloc_coherent(dev,len,&dma_handle,GFP_KERNEL);
    
	pr_info("\nEncryption with DMA and polling...\n");
	//printk(KERN_INFO "\nBuffer kernel virtual address = 0x%px\n", &(*buff));
    
    memcpy(buff,data,len);
    //buff[len] = '\0';
    //printk(KERN_INFO "Bufferd string(before op): %s\n", buff);

    iowrite32(len, ccbar0+DMA_DATA_LEN_OFF);
    iowrite32(dma_handle, ccbar0+DMA_ADDR_OFF);

    printk(KERN_INFO "DMA handle returned: %llx\n",  dma_handle);
	
	while(ioread32(ccbar0+DMA_CMD_OFF) & 1) ;   
      
	printk(KERN_INFO "Device is free...START OP\n");
    iowrite32(0x1, ccbar0+DMA_CMD_OFF);    //bit0 = 1 (DMA), bit1 = 0 (encryption), bit2 = 0 (without interrupt)
    
	while(ioread32(ccbar0+DMA_CMD_OFF) & 1);

    //data[len] = '\0';
    //printk(KERN_INFO "DMA address is(after operation): 0x%x\n", ioread32(ccbar0+DMA_ADDR_OFF));
    //printk(KERN_INFO "Original string is: %s\n", data);
    //printk(KERN_INFO "Buffered string (after encryption) is: %s\n", buff);
    //printk(KERN_INFO "DMA command register (after op): 0x%x\n", ioread32(ccbar0+DMA_CMD_OFF));

    memcpy(data,buff,len);
    dma_free_coherent(dev,len,buff,dma_handle);
}

void decryption_dma_poll(char *data, u64 length)
{
	struct pci_dev *pdev = cc_info.pdev;
    u8 __iomem *ccbar0 = cc_info.ccbar0;
	dma_addr_t dma_handle;
	struct device *dev;
	u32 len;
	char *buff;

	len = (u32)length;
	dev = &pdev->dev;
	buff = dma_alloc_coherent(dev,len,&dma_handle,GFP_KERNEL);

	pr_info("\nDecryption with DMA and polling...\n");
    //printk(KERN_INFO "\nBuffer kernel virtual address = 0x%px\n", &(*buff));
	
	memcpy(buff,data,len);
	//buff[len] = '\0';
    //printk(KERN_INFO "Bufferd string(before op): %s\n", buff);

    iowrite32(len, ccbar0+DMA_DATA_LEN_OFF);
    iowrite32(dma_handle, ccbar0+DMA_ADDR_OFF);

    printk(KERN_INFO "DMA handle returned: %llx\n",  dma_handle);

	while(ioread32(ccbar0+DMA_CMD_OFF) & 1) ;

    printk(KERN_INFO "Device is free...START OP\n");
    iowrite32(0x1|0x2, ccbar0+DMA_CMD_OFF);    //bit0 = 1 (DMA), bit1 = 1 (decryption), bit2 = 0 (without interrupt)
    
	while(ioread32(ccbar0+DMA_CMD_OFF) & 1) ;

	//data[len] = '\0';
	//printk(KERN_INFO "DMA address is(after operation): 0x%x\n", ioread32(ccbar0+DMA_ADDR_OFF));
	//printk(KERN_INFO "Original string is: %s\n", data);
	//printk(KERN_INFO "Buffered string (after op) is: %s\n", buff);
	//printk(KERN_INFO "DMA command register (after op): 0x%x\n", ioread32(ccbar0+DMA_CMD_OFF));

	memcpy(data,buff,len);
	dma_free_coherent(dev,len,buff,dma_handle);
}

static int cryptocard_fopen(struct inode *inode, struct file *file)
{
    struct cryptocard_config *config;  //fd specifice device configuration

	atomic_inc(&device_opened);
    try_module_get(THIS_MODULE);  //for refernce count of the module so that module cannot be unloaded if not zero

	config = kmalloc(sizeof(struct cryptocard_config), GFP_KERNEL);
	if (!config) {
    	printk(KERN_INFO "config allocation failed \n");
		return -1;
	}

	config->dma = 0;
	config->interrupt = 0;
	config->isKeyset = 0;
	config->isConfigset = 0;

	file->private_data = config;	
	
    printk(KERN_INFO "Device opened successfully\n");
    return 0;
}

static int cryptocard_frelease(struct inode *inode, struct file *file)
{
        atomic_dec(&device_opened);
        module_put(THIS_MODULE);
        printk(KERN_INFO "Device closed successfully\n");

		kfree(file->private_data);
        return 0;
}

static ssize_t cryptocard_fread(struct file *filp,
                           char *buffer,
                           size_t length,
                           loff_t * offset)
{
        printk(KERN_INFO "In read\n");
        //if (copy_to_user(buffer,&gptr,sizeof(unsigned long)) == 0)
            // return sizeof(unsigned long);
        return 0;
}

static ssize_t cryptocard_fwrite(struct file *filp, const char *buff, size_t len, loff_t * off)
{

        printk(KERN_INFO "In write %s\n",buff);
        //if(copy_from_user(&gptr,buff,sizeof(unsigned long)) == 0)
          //   return sizeof(unsigned long);
        return 0;
}

static int cryptocard_fmmap(struct file *file, struct vm_area_struct *vma)
{
	unsigned long offset, mmio_start = cc_info.mmio_start;
	int err;
	//char * data;

	printk(KERN_INFO "Inside mmap...\n");
	printk(KERN_INFO "vm start = 0x%lx, vma end = 0x%lx\n", vma->vm_start, vma->vm_end);
	printk(KERN_INFO "vm_pgoff = 0x%lx\n", vma->vm_pgoff);
	
	offset = vma->vm_pgoff<<PAGE_SHIFT; //vm_pgoff has no of pages NOT no of bytes in multiple of page size, passed in mmap
	//check here: (vm_end -vm_start)+offset > size of bar0 --- out of range.
	offset = mmio_start + offset;  // mmio_start is starting physical address of device memory bar0

//	vma->vm_flags |= VM_IO;	
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	
	//updating process page table for new VMA
	err = io_remap_pfn_range(vma, vma->vm_start, offset>>PAGE_SHIFT, vma->vm_end-vma->vm_start, vma->vm_page_prot);
	if(err) {
		printk(KERN_INFO " io_remap_pfn_range() function error...\n");
		return -EAGAIN;
	}	
	
	//data = (char *)vma->vm_start;
	//data = data + 0xa8;
	//memcpy(data, "Hello CS730!", 12);
	//memcpy(read, data, 12);
	//read[12] = '\0';
	//printk(KERN_INFO "mmap: read at 0xa8: %s \n", read);
	printk(KERN_INFO "mmap: 0x%x \n", *((u32 *)vma->vm_start));
	return 0;		
}

static long cryptocard_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	u8 a, b, interrupt, dma, isConfigset, __iomem *ccbar0 = cc_info.ccbar0;
	u8 isMapped;
	char *buff;
	u64 length;
	u32 err;
	//struct cc_key *cckey = (struct cc_key *)arg;
	struct cc_key *cckey;
	struct cc_config *cfg;
	struct cc_op *ccop;
	struct cryptocard_config *rconfig = (struct cryptocard_config *)file->private_data;	

	switch (cmd)
	{
		case SET_KEY:
			cckey = (struct cc_key *)arg;
			rconfig->a = cckey->a;
			rconfig->b = cckey->b;
			rconfig->isKeyset = 1;
						
			printk(KERN_INFO "%d %d 0x%x\n",rconfig->a,rconfig->b,ioread32(ccbar0+0x0));
			//iowrite32(a<<8 | b, ccbar0 + KEY_OFF); 
    		//printk(KERN_INFO "\nfile private data = 0x%px\n", file->private_data); ///////////////
			break;
		case SET_CONFIG:
			//printk(KERN_INFO "inside config...\n");
			cfg = (struct cc_config *)arg;
			if (cfg->mode_int_dma == 0) // 0 = interrupt and 1 = dma
				rconfig->interrupt = cfg->set;
			else 	
				rconfig->dma = cfg->set;	
			
			if (!rconfig->isConfigset)	
				rconfig->isConfigset = 1;
			
			break;
		case ENCRYPT:
			spin_lock(&cc_spinlock);

			a = rconfig->a;
			b = rconfig->b;
			interrupt = rconfig->interrupt;
			dma = rconfig->dma;
			isConfigset = rconfig->isConfigset;
			printk(KERN_INFO "%d %d %d %d %d\n",rconfig->a,rconfig->b,rconfig->dma,rconfig->interrupt,rconfig->isConfigset);
				
			ccop = (struct cc_op *)arg;
			length = ccop->length;
			isMapped = ccop->isMapped;
    		iowrite32(a<<8|b, ccbar0 + KEY_OFF);

			if(isMapped == 0) {
				buff = kmalloc(length+1, GFP_KERNEL);
				err = copy_from_user(buff, ccop->addr, length);
				//printk(KERN_INFO " ioctl-encrypt: buff = %s\n", buff);

				//iowrite32(a<<8|b, ccbar0 + KEY_OFF);
				if (dma == 0) {							// MMIO ------------------Encryption---------------
					if (interrupt == 0) {
						//iowrite32(a<<8|b, ccbar0 + KEY_OFF);
						encryption_mmio_poll(buff, length);
						copy_to_user(ccop->addr, buff, length);
					}
					else {
						encryption_mmio_interrupt(buff, length);	
						copy_to_user(ccop->addr, buff, length);
					}
				}
				else {								// DMA 
					if (interrupt == 0) {
                    	encryption_dma_poll(buff, length);
						copy_to_user(ccop->addr, buff, length);
					}
					else {
                    	encryption_dma_interrupt(buff, length);
						copy_to_user(ccop->addr, buff, length);
					}
				}
				spin_unlock(&cc_spinlock);
			}
			else {
				if(interrupt == 0) {
					encryption_mmap_polling(length);
				}
				else
					encryption_mmap_interrupt(length);
			}

			break;
		case DECRYPT:
			spin_lock(&cc_spinlock);

			a = rconfig->a;
            b = rconfig->b;
            interrupt = rconfig->interrupt;
            dma = rconfig->dma;
            isConfigset = rconfig->isConfigset;
            printk(KERN_INFO "%d %d %d %d %d\n",rconfig->a,rconfig->b,rconfig->dma,rconfig->interrupt,rconfig->isConfigset);
			
			ccop = (struct cc_op *)arg;
            length = ccop->length;
			isMapped = ccop->isMapped;
    		iowrite32(a<<8|b, ccbar0 + KEY_OFF);

			if(isMapped == 0) {
            	buff = kmalloc(length+1, GFP_KERNEL);
            	err = copy_from_user(buff, ccop->addr, length);
			
    			//iowrite32(a<<8|b, ccbar0 + KEY_OFF);
            	if (dma == 0) {								// MMIO----------------------Decryption-------------------
                	if (interrupt == 0) {
    					//iowrite32(a<<8|b, ccbar0 + KEY_OFF);
                    	decryption_mmio_poll(buff, length);
						copy_to_user(ccop->addr, buff, length);
					}
               	  	else {
						decryption_mmio_interrupt(buff, length);	
						copy_to_user(ccop->addr, buff, length);
					}
            	}
            	else {										// DMA
                	if (interrupt == 0) {
                    	decryption_dma_poll(buff, length);
						copy_to_user(ccop->addr, buff, length);
					}
                	else {
                    	decryption_dma_interrupt(buff, length);
						copy_to_user(ccop->addr, buff, length);
					}
            	}
				
				spin_unlock(&cc_spinlock);
			}
			else 
			{	
				if(interrupt == 0) {
					decryption_mmap_polling(length);
				}
				else
					decryption_mmap_interrupt(length);
			}
			break;
		default:
			return -EINVAL;
	}	

	return 0;
}

static struct file_operations fops = {
	.read = cryptocard_fread,
    .write = cryptocard_fwrite,
	.open = cryptocard_fopen,
	.mmap = cryptocard_fmmap,
	.unlocked_ioctl = cryptocard_ioctl,
    .release = cryptocard_frelease,
};

static char *cryptocard_devnode(struct device *dev, umode_t *mode)
{
	if (mode && dev->devt == MKDEV(major, 0))
    	*mode = 0666;	// set /dev/cryptocard file mode to rw_rw_rw_
    return NULL;
}

static int cryptocard_chardev_setup(void)
{
	int err;
	printk(KERN_INFO "Char Device registration...\n");
	
	major = register_chrdev(0, DRIVER_NAME, &fops);
	
	err = major;
    if (err < 0) {
    	printk(KERN_ALERT "Registering char device failed with %d\n", major);
        goto error_regdev;    
	 }

	cc_class = class_create(THIS_MODULE, DRIVER_NAME);	
    err = PTR_ERR(cc_class);    
	if (IS_ERR(cc_class))
   		goto error_class;

	cc_class->devnode = cryptocard_devnode;    	// to assign mode 0666        
	
	cc_device = device_create(cc_class, NULL, MKDEV(major, 0),NULL, DRIVER_NAME);
    err = PTR_ERR(cc_device);
    if (IS_ERR(cc_device))
		goto error_device;
	
	
    printk(KERN_INFO "\ncc_device = 0x%px\n", cc_device); ///////////////
	printk(KERN_INFO "char device major number %d.\n", major);                                                     
    atomic_set(&device_opened, 0);
	
	return 0;

error_device:
	class_destroy(cc_class);
error_class:
	unregister_chrdev(major, DRIVER_NAME);
error_regdev:
	return  err;
	
}
static int cryptocard_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	int bar, err;
    u16 vendorid, deviceid;
    unsigned long mmio_start,mmio_len;

	struct cryptocard_mm *cc_mmregion;
	u8 irq,  __iomem *ccbar0;
    u32 live = 0xaaaaaaaa;  // on read : 0x55555555
    //u32 a=30, b=17;

    pci_read_config_word(pdev, PCI_VENDOR_ID, &vendorid);
    pci_read_config_word(pdev, PCI_DEVICE_ID, &deviceid);

    printk(KERN_INFO "Vendor ID: 0x%X Device ID: 0x%X\n", vendorid, deviceid);

	err = pci_enable_device(pdev);

	bar = pci_select_bars(pdev, IORESOURCE_MEM); // this returns number of bar regions set as memory space
    err = pci_enable_device_mem(pdev);  //enable the device
    err = pci_request_region(pdev, bar, DRIVER_NAME);  // this sets all device memory regions either as IO space or memory space

    mmio_start = pci_resource_start(pdev, 0);
    mmio_len = pci_resource_len(pdev, 0);
	printk(KERN_INFO "mmio start = 0x%lX, mmio_len = 0x%lX\n", mmio_start, mmio_len);

	cc_mmregion = kzalloc(sizeof(struct cryptocard_mm), GFP_KERNEL);
	cc_mmregion->ccbar0 = ioremap(mmio_start, mmio_len);
	ccbar0 = cc_mmregion->ccbar0;
	
	pci_set_master(pdev);
	pci_set_drvdata(pdev, cc_mmregion);
	cc_info.ccbar0 = ccbar0;
	cc_info.pdev = pdev;
	cc_info.mmio_start = mmio_start;

    iowrite32(live, (ccbar0 + LIVE_OFF));
    //iowrite32(a<<8|b, ccbar0 + 0x8);
	
	printk(KERN_INFO "Device unique bytes: 0x%08X, live: 0x%08X\n",*((u32 *)ccbar0), ioread32(ccbar0+LIVE_OFF));
	//printk(KERN_INFO "a: 0x%X, b: 0x%X\n",a, b);
	printk(KERN_INFO "Data addres register: 0x%08X\n", ioread32(ccbar0+DATA_OFF));
	

    printk(KERN_INFO "\npdev = 0x%px, ccbar0 = 0x%px\n", pdev, ccbar0);
	cryptocard_chardev_setup();
	
	pci_alloc_irq_vectors(pdev,1,1,PCI_IRQ_MSI);
	irq = pci_irq_vector(pdev,0);
	request_threaded_irq(irq, cryptocard_irq_handle, NULL, 0, DRIVER_NAME, pdev);
	
	printk("irq assigned = 0x%x\n", irq);
	//test_encryption(pdev);
	//test_decryption(pdev);
	//test_dma(pdev);
	//encryption_mmio_interrupt();

    return 0;
}


static void cryptocard_remove(struct pci_dev *pdev)
{
	struct cryptocard_mm *cc_mmregion;
	u8 irq, __iomem *ccbar0;

	device_destroy(cc_class, MKDEV(major, 0));
    class_destroy(cc_class);
    unregister_chrdev(major, DRIVER_NAME);

	cc_mmregion = pci_get_drvdata(pdev);
	ccbar0 = cc_mmregion->ccbar0;
	if(cc_mmregion) {
		if(ccbar0) {
			iounmap(ccbar0);
		}

		kfree(cc_mmregion);
	}
	
	irq = pci_irq_vector(pdev,0);
	free_irq(irq, pdev);
	pci_free_irq_vectors(pdev);

	pci_clear_master(pdev);
	pci_release_region(pdev, pci_select_bars(pdev, IORESOURCE_MEM));    
    pci_disable_device(pdev);	
}



MODULE_LICENSE("GPL");
MODULE_AUTHOR("Niraj Kundu");
MODULE_DESCRIPTION("Driver for PCI Device CryptoCard");
MODULE_VERSION("0.1");

module_init(cryptocard_entry);
module_exit(cryptocard_exit);
