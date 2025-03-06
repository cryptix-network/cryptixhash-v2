#include <iostream>
#include <string>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <unistd.h>


// The detection of logs, kernel processes, and drivers can obviously be obfuscated or hidden. This creates significant work for manufacturers to detect and prevent it, or to find a bypass method.

// However, hardware checks that need to be added are not as easily obfuscated or bypassed.

// Possible methods for hardware detection:

// Physical device detection: Directly identifying FPGA or ASIC hardware within the system.
// Real-time device communication: Monitoring actual communication and interaction between hardware components in the system.
// Hardware identification via direct access: Identifying hardware components through direct access to system resources (e.g., through the PCI bus or low-level APIs).

// Todo: 
// - Add Windows compatibly
// - Add Hardware Detection
// - Add encryption
// - Code Obfuscation on final Code
// - Add anti-debugging techniques
// - Add Runtime Decryption
// - Add hash-based integrity check


extern "C" {
    bool CheckFPGAOrASIC() {
        bool hardwareDetected = false;
        std::string command;
        FILE *fp = nullptr;
        
        // FPGA drivers are loaded as kernel modules
        command = "lsmod | grep -i \"xilinx\" || lsmod | grep -i \"altera\" || lsmod | grep -i \"cyclone\" || lsmod | grep -i \"arria\" || lsmod | grep -i \"stratix\" || lsmod | grep -i \"lattice\" || lsmod | grep -i \"microsemi\" || lsmod | grep -i \"achronix\" || lsmod | grep -i \"quicklogic\"";
        fp = popen(command.c_str(), "r");
        if (fp == nullptr) {
            std::cerr << "Error: Cannot retrieve driver information (lsmod)." << std::endl;
            return false; 
        }

        char path[1035];
        while (fgets(path, sizeof(path), fp) != nullptr) {
            std::cout << "FPGA driver found: " << path;
            hardwareDetected = true;
        }
        fclose(fp);

        // FPGA devices via PCI
        if (!hardwareDetected) {
            command = "lspci | grep -i \"xilinx\" || lspci | grep -i \"altera\" || lspci | grep -i \"cyclone\" || lspci | grep -i \"arria\" || lspci | grep -i \"stratix\" || lspci | grep -i \"intel\" || lspci | grep -i \"lattice\" || lspci | grep -i \"microsemi\" || lspci | grep -i \"achronix\" || lspci | grep -i \"quicklogic\"";
            fp = popen(command.c_str(), "r");
            if (fp == nullptr) {
                std::cerr << "Error: Cannot retrieve PCI device list (lspci)." << std::endl;
                return false; 
            }
            
            while (fgets(path, sizeof(path), fp) != nullptr) {
                std::cout << "FPGA device found via PCI: " << path;
                hardwareDetected = true;
            }
            fclose(fp);
        }

        // dmesg logs for FPGA/ASIC related messages
        if (!hardwareDetected) {
            command = "dmesg | grep -i \"xilinx\" || dmesg | grep -i \"altera\" || dmesg | grep -i \"cyclone\" || dmesg | grep -i \"arria\" || dmesg | grep -i \"stratix\" || dmesg | grep -i \"lattice\" || dmesg | grep -i \"microsemi\" || dmesg | grep -i \"achronix\" || dmesg | grep -i \"quicklogic\" || dmesg | grep -i \"asic\" || dmesg | grep -i \"bitmain\" || dmesg | grep -i \"canaan\" || dmesg | grep -i \"innosilicon\" || dmesg | grep -i \"ebang\" || dmesg | grep -i \"microbt\"";
            fp = popen(command.c_str(), "r");
            if (fp == nullptr) {
                std::cerr << "Error: Cannot retrieve dmesg logs." << std::endl;
                return false; 
            }
            
            while (fgets(path, sizeof(path), fp) != nullptr) {
                std::cout << "FPGA or ASIC detected in dmesg logs: " << path;
                hardwareDetected = true;
            }
            fclose(fp);
        }

        // FPGA/ASIC devices with lshw
        if (!hardwareDetected) {
            command = "lshw -class system | grep -i \"fpga\" || lshw -class system | grep -i \"asic\" || lshw -class system | grep -i \"xilinx\" || lshw -class system | grep -i \"altera\" || lshw -class system | grep -i \"cyclone\" || lshw -class system | grep -i \"arria\" || lshw -class system | grep -i \"stratix\" || lshw -class system | grep -i \"lattice\" || lshw -class system | grep -i \"microsemi\" || lshw -class system | grep -i \"achronix\" || lshw -class system | grep -i \"quicklogic\"";
            fp = popen(command.c_str(), "r");
            if (fp == nullptr) {
                std::cerr << "Error: Cannot retrieve hardware information (lshw)." << std::endl;
                return false; 
            }
            
            while (fgets(path, sizeof(path), fp) != nullptr) {
                std::cout << "FPGA or ASIC device detected with lshw: " << path;
                hardwareDetected = true;
            }
            fclose(fp);
        }

        // FPGA-related software or processes
        if (!hardwareDetected) {
            command = "ps aux | grep -i \"xilinx\" || ps aux | grep -i \"altera\" || ps aux | grep -i \"cyclone\" || ps aux | grep -i \"arria\" || ps aux | grep -i \"stratix\" || ps aux | grep -i \"lattice\" || ps aux | grep -i \"microsemi\" || ps aux | grep -i \"achronix\" || ps aux | grep -i \"quicklogic\"";
            fp = popen(command.c_str(), "r");
            if (fp == nullptr) {
                std::cerr << "Error: Cannot retrieve process list (ps)." << std::endl;
                return false; 
            }

            while (fgets(path, sizeof(path), fp) != nullptr) {
                std::cout << "FPGA-related processes detected: " << path;
                hardwareDetected = true;
            }
            fclose(fp);
        }

        // ASIC-related software or processes
        if (!hardwareDetected) {
            command = "ps aux | grep -i \"bitmain\" || ps aux | grep -i \"canaan\" || ps aux | grep -i \"innosilicon\" || ps aux | grep -i \"ebang\" || ps aux | grep -i \"microbt\"";
            fp = popen(command.c_str(), "r");
            if (fp == nullptr) {
                std::cerr << "Error: Cannot retrieve ASIC-related processes." << std::endl;
                return false; 
            }

            while (fgets(path, sizeof(path), fp) != nullptr) {
                std::cout << "ASIC-related processes detected: " << path;
                hardwareDetected = true;
            }
            fclose(fp);
        }

        if (hardwareDetected) {
            std::cout << "FPGA or ASIC detected. Mining is not allowed." << std::endl;
            return false;
        }

        std::cout << "No FPGA or ASIC detected. Proceeding with mining..." << std::endl;
        return true; 
    }
}
