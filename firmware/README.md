# Aether Firmware

Controller firmware for the Nordic nRF5340-DK development board.

## Requirements

- Zephyr RTOS SDK v3.6+
- Nordic nRF Connect SDK v2.6+
- Two nRF5340-DK boards for end-to-end testing

## Building

```bash
west build -b nrf5340dk_nrf5340_cpuapp
west flash
```

## Status

Not yet implemented. Hardware bring-up begins after the simulator conformance suite is stable.
