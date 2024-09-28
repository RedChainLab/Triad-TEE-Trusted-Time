#include "Enclave_t.h"
#include "ENode.h"
#include <map>

#define ENCLAVE_MGR "[ENode Mgr]> "

extern std::map<int /*port*/, ENode*> nodes;

int ecall_init(uint16_t _port)
{
    printf("%sInitializing enclave node...\r\n", ENCLAVE_MGR);
    if(nodes.find(_port) != nodes.end())
    {
        printf("%sNode already exists.\r\n", ENCLAVE_MGR);
        return SOCKET_ALREADY_EXISTS;
    }
    printf("%sNode does not exist yet. Creating...\r\n", ENCLAVE_MGR);
    nodes.emplace(_port, new ENode(_port));
    return SUCCESS;
}

int ecall_stop(uint16_t _port)
{
    printf("%sStopping enclave...\r\n", ENCLAVE_MGR);
    if(nodes.find(_port) == nodes.end())
    {
        printf("%sNode does not exist.\r\n", ENCLAVE_MGR);
        return SOCKET_ALREADY_EXISTS;
    }
    delete nodes[_port];
    nodes.erase(_port);
    printf("%sEnclave stopped.\r\n", ENCLAVE_MGR);
    return SUCCESS;
}

int ecall_start(uint16_t _port)
{
    printf("%sStarting enclave logic...\r\n", ENCLAVE_MGR);
    if(nodes.find(_port) == nodes.end())
    {
        printf("%sNode does not exist...\r\n", ENCLAVE_MGR);
        return SOCKET_ALREADY_EXISTS;
    }
    //nodes[_port]->loop_recvfrom();
    nodes[_port]->monitor(500, 7, 2);
    printf("%sEnclave logic started.\r\n", ENCLAVE_MGR);
    return SUCCESS;
}

int ecall_add_sibling(uint16_t _port, const char* hostname, uint16_t port)
{
    printf("%sAdding sibling at %s:%d to node at %d...\r\n", ENCLAVE_MGR, hostname, port, _port);
    if(nodes.find(_port) == nodes.end())
    {
        printf("%sNode at %d does not exist...\r\n", ENCLAVE_MGR, _port);
        return SOCKET_ALREADY_EXISTS;
    }
    nodes[_port]->add_sibling(std::string(hostname), port);
    printf("%sSibling at %s:%d added to node at %d.\r\n", ENCLAVE_MGR, hostname, port, _port);
    return SUCCESS;
}
