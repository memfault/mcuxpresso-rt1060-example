/*
 * Copyright (c) 2016, Freescale Semiconductor, Inc.
 * Copyright 2016-2020 NXP
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*******************************************************************************
 * Includes
 ******************************************************************************/
#include "httpsclient.h"
#include "pin_mux.h"
#include "clock_config.h"
#include "board.h"
#include "lwip/netifapi.h"
#include "lwip/opt.h"
#include "lwip/tcpip.h"
#include "lwip/dhcp.h"
#include "lwip/prot/dhcp.h"
#include "netif/ethernet.h"
#include "enet_ethernetif.h"
#include "fsl_phy.h"
#include "ksdk_mbedtls.h"
#include "timers.h"

#include "fsl_debug_console.h"

#include "fsl_phyksz8081.h"
#include "fsl_enet_mdio.h"
#include "fsl_gpio.h"
#include "fsl_iomuxc.h"

#include "memfault/components.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/* MAC address configuration. */
#define configMAC_ADDR                     \
    {                                      \
        0x02, 0x12, 0x13, 0x10, 0x15, 0x25 \
    }

/* Address of PHY interface. */
#define EXAMPLE_PHY_ADDRESS BOARD_ENET0_PHY_ADDRESS

/* MDIO operations. */
#define EXAMPLE_MDIO_OPS enet_ops

/* PHY operations. */
#define EXAMPLE_PHY_OPS phyksz8081_ops

/* ENET clock frequency. */
#define EXAMPLE_CLOCK_FREQ CLOCK_GetFreq(kCLOCK_IpgClk)


#ifndef EXAMPLE_NETIF_INIT_FN
/*! @brief Network interface initialization function. */
#define EXAMPLE_NETIF_INIT_FN ethernetif0_init
#endif /* EXAMPLE_NETIF_INIT_FN */

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/

static mdio_handle_t mdioHandle = {.ops = &EXAMPLE_MDIO_OPS};
static phy_handle_t phyHandle   = {.phyAddr = EXAMPLE_PHY_ADDRESS, .mdioHandle = &mdioHandle, .ops = &EXAMPLE_PHY_OPS};

/*******************************************************************************
 * Code
 ******************************************************************************/
void BOARD_InitModuleClock(void)
{
    const clock_enet_pll_config_t config = {.enableClkOutput = true, .enableClkOutput25M = false, .loopDivider = 1};
    CLOCK_InitEnetPll(&config);
}

void delay(void)
{
    volatile uint32_t i = 0;
    for (i = 0; i < 1000000; ++i)
    {
        __asm("NOP"); /* delay */
    }
}



void *pvPortCalloc(size_t num, size_t size)
{
    void *ptr;
    int allocSize = num * size;

    ptr = pvPortMalloc(allocSize);
    if (ptr != NULL)
    {
        memset(ptr, 0, allocSize);
    }

    return ptr;
}

// Try to bring up the network interface. 0 for success, non-zero for failure
static int netifinit(void)
{
    static struct netif netif;
    ip4_addr_t netif_ipaddr, netif_netmask, netif_gw;
    ethernetif_config_t enet_config = {
        .phyHandle  = &phyHandle,
        .macAddress = configMAC_ADDR,
    };

    mdioHandle.resource.csrClock_Hz = EXAMPLE_CLOCK_FREQ;

    IP4_ADDR(&netif_ipaddr, 0, 0, 0, 0);
    IP4_ADDR(&netif_netmask, 0, 0, 0, 0);
    IP4_ADDR(&netif_gw, 0, 0, 0, 0);

    tcpip_init(NULL, NULL);

    err_t err =
        netifapi_netif_add(&netif, &netif_ipaddr, &netif_netmask, &netif_gw,
                           &enet_config, EXAMPLE_NETIF_INIT_FN, tcpip_input);
    if (err != ERR_OK) {
      PRINTF("\n\r!!! Failed to initialize ethernetif !!!\n\r");
      return -1;
    }
    netifapi_netif_set_default(&netif);
    netifapi_netif_set_up(&netif);

    PRINTF("Getting IP address from DHCP ...\n");
    netifapi_dhcp_start(&netif);

    struct dhcp *dhcp;
    dhcp = netif_dhcp_data(&netif);

    const int retry_time_ms = 10 * 1000;
    const TickType_t retry_ticks = retry_time_ms / portTICK_PERIOD_MS;
    int retry_count = retry_ticks / 100;
    while ((dhcp->state != DHCP_STATE_BOUND) && (retry_count > 0))
    {
        vTaskDelay(100);
        retry_count--;
    }

    if (!retry_count) {
        PRINTF("DHCP failed!\n");
        return 1;
    }

    if (dhcp->state == DHCP_STATE_BOUND)
    {
        PRINTF("\r\n IPv4 Address     : %u.%u.%u.%u\r\n", ((u8_t *)&netif.ip_addr.addr)[0],
               ((u8_t *)&netif.ip_addr.addr)[1], ((u8_t *)&netif.ip_addr.addr)[2], ((u8_t *)&netif.ip_addr.addr)[3]);
    }
    PRINTF("DHCP OK\n");

    return 0;
}

static bool netif_up = false;
static int prv_init_netif(void) {
    if (!netif_up) {
        netif_up = !netifinit();
        if (!netif_up) {
            PRINTF("Failed to initialize netif\n");
            return 1;
        }
        PRINTF("Netif initialized!\n");
    }
    return 0;
}

static int prv_upload_memfault_data(void) {
    if (!netif_up) {
        return 1;
    }
    // this function will post any buffered memfault chunks
    https_client_tls_init();

    return 0;
}

static void prv_memfault_upload_timer_callback(MEMFAULT_UNUSED TimerHandle_t handle) {
    if(!memfault_packetizer_data_available()) {
        return;
    }

    prv_upload_memfault_data();
}

static void prv_initialize_periodic_upload_timer(void) {
  // create a timer that will upload any data if available
  const char *const pcTimerName = "MemfaultUploadTimer";
  const int interval_in_seconds = 20;
  const TickType_t xTimerPeriodInTicks = pdMS_TO_TICKS(1000 * interval_in_seconds);

  TimerHandle_t timer;

#if MEMFAULT_FREERTOS_PORT_USE_STATIC_ALLOCATION != 0
  static StaticTimer_t s_task_watchdog_timer_context;
  timer = xTimerCreateStatic(pcTimerName, xTimerPeriodInTicks, pdTRUE, NULL,
                             prv_memfault_upload_timer_callback,
                             &s_task_watchdog_timer_context);
#else
  timer = xTimerCreate(pcTimerName, xTimerPeriodInTicks, pdTRUE, NULL,
                       prv_memfault_upload_timer_callback);
#endif

  MEMFAULT_ASSERT(timer != 0);

  xTimerStart(timer, 0);
}

static void blinky_task(void *arg) {
  (void)arg;

  // set up GPIO1.8 as output for LED
  const gpio_pin_config_t gpio_config = {
      .direction = kGPIO_DigitalOutput,
      .outputLogic = 0U,
      .interruptMode = kGPIO_NoIntmode,
  };
  GPIO_PinInit(GPIO1, 8, &gpio_config);
  IOMUXC_SetPinMux(IOMUXC_GPIO_AD_B0_08_GPIO1_IO08, 0U);
  IOMUXC_SetPinConfig(IOMUXC_GPIO_AD_B0_08_GPIO1_IO08, 0x10B0U);

  uint8_t output = 0;
  while (1) {
    GPIO_PinWrite(GPIO1, 8, output ^= 1);
    vTaskDelay(500 / portTICK_PERIOD_MS);
  }
}

static int send_char(char c) {
    PRINTF("%c", c);
    return 0;
}

static sMemfaultShellImpl memfault_shell_impl = {
    .send_char = send_char,
};

static int memfault_demo_cli_cmd_post_chunks(MEMFAULT_UNUSED int argc, MEMFAULT_UNUSED char *argv[]) {
    if(!memfault_packetizer_data_available()) {
        PRINTF("No Memfault data to send!\n");
        return 0;
    }

    if(!netif_up) {
        PRINTF("Network not up!\n");
        return 0;
    }

    return prv_upload_memfault_data();
}

// Define a custom console table to add the post_chunks command
static const sMemfaultShellCommand s_memfault_shell_commands[] = {
  {"get_core", memfault_demo_cli_cmd_get_core, "Get coredump info"},
  {"clear_core", memfault_demo_cli_cmd_clear_core, "Clear an existing coredump"},
  {"crash", memfault_demo_cli_cmd_crash, "Trigger a crash"},
  {"trigger_logs", memfault_demo_cli_cmd_trigger_logs, "Trigger capture of current log buffer contents"},
  {"drain_chunks",  memfault_demo_drain_chunk_data, "Flushes queued Memfault data. To upload data see https://mflt.io/posting-chunks-with-gdb"},
  {"trace", memfault_demo_cli_cmd_trace_event_capture, "Capture an example trace event"},
  {"get_device_info", memfault_demo_cli_cmd_get_device_info, "Get device info"},
  {"reboot", memfault_demo_cli_cmd_system_reboot, "Reboot system and tracks it with a trace event"},
  {"export", memfault_demo_cli_cmd_export, "Export base64-encoded chunks. To upload data see https://mflt.io/chunk-data-export"},
  {"post_chunks", memfault_demo_cli_cmd_post_chunks, "Manually trigger uploading chunks to Memfault"},
  {"help", memfault_shell_help_handler, "Lists all commands"},
};
// These definitions override the default implementation of the command table
const sMemfaultShellCommand *const g_memfault_shell_commands = s_memfault_shell_commands;
const size_t g_memfault_num_shell_commands = MEMFAULT_ARRAY_SIZE(s_memfault_shell_commands);

static void console_task(void *arg) {
    PRINTF("\n\nStarting netif...\n");

    if(prv_init_netif() != 0) {
        PRINTF("Failed to initialize network. post_chunks will not work\n");
    }

    // now that the netif is up, safe to start the blinky task (I didn't debug
    // why this interferes with that task, but it seems to)
    if(!xTaskCreate(blinky_task, "blinky_task", 100, NULL, 2 /* just higher priority than console */, NULL)) {
        PRINTF("Failed to create blinky_task\r\n");
    }

    prv_initialize_periodic_upload_timer();

    while (1) {
        int c = GETCHAR();
        if (c > 0){
            memfault_demo_shell_receive_char(c);
        }
        vTaskDelay(1);
    }
}

/*!
 * @brief Main function.
 */
int main(void)
{
    gpio_pin_config_t gpio_config = {kGPIO_DigitalOutput, 0, kGPIO_NoIntmode};

    BOARD_ConfigMPU();
    BOARD_InitBootPins();
    BOARD_InitBootClocks();
    BOARD_InitDebugConsole();
    BOARD_InitModuleClock();

    IOMUXC_EnableMode(IOMUXC_GPR, kIOMUXC_GPR_ENET1TxClkOutputDir, true);

    GPIO_PinInit(GPIO1, 9, &gpio_config);
    GPIO_PinInit(GPIO1, 10, &gpio_config);
    /* pull up the ENET_INT before RESET. */
    GPIO_WritePinOutput(GPIO1, 10, 1);
    GPIO_WritePinOutput(GPIO1, 9, 0);
    delay();
    GPIO_WritePinOutput(GPIO1, 9, 1);
    CRYPTO_InitHardware();

    memfault_platform_boot();
    memfault_demo_shell_boot(&memfault_shell_impl);

    mdioHandle.resource.csrClock_Hz = EXAMPLE_CLOCK_FREQ;

    if(!xTaskCreate(console_task, "console_task", 2000, NULL, 1 /* low priority */, NULL)) {
        PRINTF("Failed to create console_task\r\n");
    }

     /* Run RTOS */
     vTaskStartScheduler();

    /* Should not reach this statement */
    for (;;)
        ;
}
